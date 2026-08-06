use base64::{Engine, engine::general_purpose::STANDARD};
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

use crate::{
    error::VerifyError,
    types::{Claims, OfflineValidation},
};

const HEADER: &str = "-----BEGIN LICENSE FILE-----";
const FOOTER: &str = "-----END LICENSE FILE-----";

pub struct Verifier {
    pub(crate) decoding_key: DecodingKey,
    pub(crate) kid: String,
    pub(crate) fingerprint: Option<String>,
    #[allow(dead_code)]
    pub(crate) user_id: Option<String>,
    #[allow(dead_code)]
    pub(crate) product_code: Option<String>,
}

impl Verifier {
    fn decode_pem(&self, certificate: &str) -> Result<String, VerifyError> {
        let trimmed = certificate.trim();
        if !trimmed.starts_with(HEADER) || !trimmed.ends_with(FOOTER) {
            return Err(VerifyError::InvalidCertificate(
                "许可文件 PEM 头尾无效".into(),
            ));
        }
        let encoded: String = trimmed[HEADER.len()..trimmed.len() - FOOTER.len()]
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        if encoded.is_empty() {
            return Err(VerifyError::InvalidCertificate("许可文件内容为空".into()));
        }
        let compact = STANDARD
            .decode(encoded)
            .map_err(|_| VerifyError::InvalidCertificate("许可文件内容不是合法 base64".into()))?;
        String::from_utf8(compact)
            .map_err(|_| VerifyError::InvalidCertificate("许可文件内容不是 UTF-8".into()))
    }

    fn check_expired(&self, payload: &OfflineValidation) -> Option<VerifyError> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let tolerance = 60;
        if now >= payload.exp.saturating_add(tolerance) {
            return Some(VerifyError::LicenseExpired(payload.exp));
        }
        None
    }

    fn check_fingerprint(&self, payload: &OfflineValidation) -> Option<VerifyError> {
        if self.fingerprint.is_none() || payload.fingerprint_sha256.is_none() {
            return None;
        }
        let fingerprint = self.fingerprint.as_deref().map(str::trim).unwrap();
        let expected_hash = payload.fingerprint_sha256.as_deref().unwrap();

        let fingerprint_hash = format!("{:x}", Sha256::digest(fingerprint.as_bytes()));
        if expected_hash
            .as_bytes()
            .ct_eq(fingerprint_hash.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Some(VerifyError::FingerprintMismatch);
        }
        None
    }

    fn check_payload(&self, payload: &OfflineValidation) -> Option<VerifyError> {
        // check expired
        if let Some(error) = self.check_expired(payload) {
            return Some(error);
        }
        if let Some(error) = self.check_fingerprint(payload) {
            return Some(error);
        }
        None
    }

    fn check_header(&self, header: &Header) -> Option<VerifyError> {
        // header must include typ
        if header.typ.as_deref() != Some("license+jwt") {
            return Some(VerifyError::InvalidCertificate(
                "JWS Header typ 必须为 license+jwt".into(),
            ));
        }
        // header alg must be EdDSA
        if header.alg != jsonwebtoken::Algorithm::EdDSA {
            return Some(VerifyError::InvalidCertificate(
                "JWS Header alg 必须为 EdDSA".into(),
            ));
        }
        // header must include kid and find the corresponding key
        if header.kid.is_none() {
            return Some(VerifyError::InvalidCertificate(
                "JWS Header 必须包含 kid".into(),
            ));
        }
        None
    }

    pub fn verify<T: Serialize + for<'de> Deserialize<'de>>(
        &self,
        certificate: &str,
    ) -> Result<Claims<T>, VerifyError> {
        let compact = self.decode_pem(certificate)?;
        let header = jsonwebtoken::decode_header(&compact)
            .map_err(|_| VerifyError::InvalidCertificate("无法解析 JWS Header".into()))?;
        if let Some(error) = self.check_header(&header) {
            return Err(error);
        }
        let kid = header.kid.as_deref().unwrap();
        if kid != self.kid {
            return Err(VerifyError::DecodingKeyMismatch(kid.to_string()));
        }

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        let token = decode::<Value>(&compact, &self.decoding_key, &validation)
            .map_err(|_| VerifyError::LicenseTampered)?;

        let payload: OfflineValidation = serde_json::from_value(token.claims)
            .map_err(|_| VerifyError::InvalidCertificate("离线许可缺少必填字段".into()))?;

        if let Some(error) = self.check_payload(&payload) {
            return Err(error);
        }

        // return the payload as Claims<T>
        let claims = Claims::new(
            payload.entitlements.clone(),
            serde_json::from_value::<T>(payload.meta.clone())
                .map_err(|err| VerifyError::MetaParseError(err.to_string()))?,
        );

        Ok(claims)
    }
}
