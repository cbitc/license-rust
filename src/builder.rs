use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use jsonwebtoken::{DecodingKey, jwk::Jwk};

use crate::{error::VerifyError, verifier::Verifier};

pub struct MissKey;
pub struct HasKey;

pub struct VerifierBuilder<T> {
    decoding_key: Option<(DecodingKey, String)>,
    fingerprint: Option<String>,
    user_id: Option<String>,
    product_code: Option<String>,
    _state: std::marker::PhantomData<T>,
}

impl Default for VerifierBuilder<MissKey> {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifierBuilder<MissKey> {
    pub fn new() -> Self {
        VerifierBuilder {
            decoding_key: None,
            fingerprint: None,
            user_id: None,
            product_code: None,
            _state: std::marker::PhantomData,
        }
    }
}

impl<T> VerifierBuilder<T> {
    pub fn decoding_key(
        mut self,
        key: &'static str,
    ) -> Result<VerifierBuilder<HasKey>, VerifyError> {
        let decoded = STANDARD_NO_PAD
            .decode(key)
            .map_err(|_| VerifyError::InvalidKey("签名密钥不是合法 base64".into()))?;
        let jwk: Jwk = serde_json::from_slice(&decoded)
            .map_err(|_| VerifyError::InvalidKey("签名密钥不是合法 JWK".into()))?;
        // jwk must include kid
        if jwk.common.key_id.is_none() {
            return Err(VerifyError::InvalidKey("该密钥缺失 kid".into()));
        }
        let decoding_key =
            DecodingKey::from_jwk(&jwk).map_err(|err| VerifyError::InvalidKey(err.to_string()))?;
        self.decoding_key = Some((decoding_key, jwk.common.key_id.unwrap()));
        Ok(VerifierBuilder {
            decoding_key: self.decoding_key,
            fingerprint: self.fingerprint,
            user_id: self.user_id,
            product_code: self.product_code,
            _state: std::marker::PhantomData,
        })
    }

    pub fn fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.fingerprint = Some(fingerprint.into());
        self
    }

    pub fn user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    pub fn product_code(mut self, product_code: impl Into<String>) -> Self {
        self.product_code = Some(product_code.into());
        self
    }
}

impl VerifierBuilder<HasKey> {
    pub fn build(self) -> Verifier {
        let (decoding_key, kid) = self.decoding_key.unwrap();
        Verifier {
            decoding_key,
            kid,
            fingerprint: self.fingerprint,
            user_id: self.user_id,
            product_code: self.product_code,
        }
    }
}
