use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

use crate::{
    claims::{Claims, PublicJwk, VerifiedLicense},
    environment::LicenseEnvironment,
    error::LicenseError,
    fingerprint,
};

#[derive(Deserialize)]
struct Header {
    alg: String,
    typ: Option<String>,
    kid: String,
}

/// 校验原语：验签 + v3 claims 校验。时间由调用方注入，便于测试。
///
/// 语义与 license-active 激活入口的本地校验完全一致：
/// header 须 `alg=EdDSA`、`typ=license+jwt`；按 kid 匹配 OKP/Ed25519 公钥验签；
/// claims 须 version 3、签发方匹配、必要声明齐全、`nbf <= now < exp` 且时间范围自洽；
/// `fingerprintSha256` 存在时须与传入指纹原始字符串相等。
pub fn verify_certificate(
    compact: &str,
    keys: &[PublicJwk],
    expected_issuer: &str,
    fingerprint: &str,
    now: i64,
) -> Result<Claims, LicenseError> {
    let parts: Vec<&str> = compact.trim().split('.').collect();
    if parts.len() != 3 {
        return Err(LicenseError::TokenFormat);
    }
    let header: Header = decode_json(parts[0])?;
    if header.alg != "EdDSA" || header.typ.as_deref() != Some("license+jwt") {
        return Err(LicenseError::TokenAlgorithm);
    }
    let jwk = keys
        .iter()
        .find(|key| key.kid == header.kid)
        .ok_or(LicenseError::SigningKeyMissing)?;
    if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
        return Err(LicenseError::SigningKeyInvalid("公钥类型不受支持".into()));
    }
    let key_bytes = URL_SAFE_NO_PAD
        .decode(&jwk.x)
        .map_err(|_| LicenseError::SigningKeyInvalid("公钥编码无效".into()))?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| LicenseError::SigningKeyInvalid("公钥长度无效".into()))?;
    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|_| LicenseError::SigningKeyInvalid("公钥无效".into()))?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| LicenseError::TokenFormat)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| LicenseError::TokenFormat)?;
    verifying_key
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .map_err(|_| LicenseError::Signature)?;

    let claims: Claims = decode_json(parts[1])?;
    validate_claims(&claims, expected_issuer, fingerprint, now)?;
    Ok(claims)
}

/// 高层入口：从本地环境读取令牌并完成校验。
///
/// - `Ok(None)`：环境中没有激活令牌（未激活）。
/// - `Ok(Some)`：令牌存在且校验通过，claims 为从令牌新鲜解析的结果。
/// - `Err`：令牌存在但校验失败（过期、被篡改、设备不符等）。
///   SDK 不做清除等破坏性动作，清理由激活入口（license-active）负责。
pub fn verify_environment(
    environment: &LicenseEnvironment,
    expected_issuer: &str,
) -> Result<Option<VerifiedLicense>, LicenseError> {
    let Some(stored) = environment.load_activation()? else {
        return Ok(None);
    };
    let fingerprint = fingerprint::current_fingerprint()?;
    let keys = environment.load_keys_with_builtin()?;
    let claims = verify_certificate(
        &stored.token,
        &keys,
        expected_issuer,
        &fingerprint,
        now_epoch(),
    )?;
    Ok(Some(VerifiedLicense::from((&stored, claims, fingerprint))))
}

fn decode_json<T: serde::de::DeserializeOwned>(encoded: &str) -> Result<T, LicenseError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| LicenseError::TokenPayload)?;
    serde_json::from_slice(&bytes).map_err(|_| LicenseError::TokenPayload)
}

fn validate_claims(
    claims: &Claims,
    expected_issuer: &str,
    fingerprint: &str,
    now: i64,
) -> Result<(), LicenseError> {
    if claims.version != 3 {
        return Err(LicenseError::Version);
    }
    if claims.iss != expected_issuer {
        return Err(LicenseError::Issuer);
    }
    if claims.sub.trim().is_empty()
        || claims.aud.trim().is_empty()
        || claims.jti.trim().is_empty()
        || claims.policy_id.trim().is_empty()
        || claims.license_key.trim().is_empty()
    {
        return Err(LicenseError::MissingClaims);
    }
    if claims
        .entitlements
        .iter()
        .any(|item| item.code.trim().is_empty())
    {
        return Err(LicenseError::Entitlements);
    }
    if now < claims.nbf {
        return Err(LicenseError::NotYetValid);
    }
    if now >= claims.exp {
        return Err(LicenseError::Expired);
    }
    if claims.iat > claims.exp || claims.nbf > claims.exp {
        return Err(LicenseError::TimeRange);
    }
    if let Some(bound) = &claims.fingerprint_sha256
        && bound != fingerprint
    {
        return Err(LicenseError::FingerprintMismatch);
    }
    Ok(())
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    use super::*;
    use crate::claims::{ActivationSource, StoredLicense};

    fn signed_token(overrides: serde_json::Value) -> (String, PublicJwk) {
        let signing = SigningKey::from_bytes(&[7_u8; 32]);
        let header = json!({"alg":"EdDSA","typ":"license+jwt","kid":"test-key"});
        let mut claims = json!({
            "version": 3, "meta": {}, "iss": "issuer", "aud": "product",
            "sub": "license", "jti": "issuance", "policyId": "policy",
            "licenseKey": "LIC-TEST", "productCode": "product",
            "productName": "产品", "policyName": "策略", "issuedAt": 100,
            "entitlements": [{"code": "FEATURE_A", "name": "功能A"}],
            "fingerprintSha256": "fingerprint",
            "iat": 100, "nbf": 100, "exp": 200
        });
        for (key, value) in overrides.as_object().unwrap() {
            claims[key] = value.clone();
        }
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let input = format!("{h}.{p}");
        let signature = signing.sign(input.as_bytes());
        let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
        let jwk = PublicJwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes()),
            kid: "test-key".into(),
            alg: Some("EdDSA".into()),
            key_use: Some("sig".into()),
        };
        (token, jwk)
    }

    #[test]
    fn verifies_valid_token() {
        let (token, key) = signed_token(json!({}));
        assert!(verify_certificate(&token, &[key], "issuer", "fingerprint", 150).is_ok());
    }

    #[test]
    fn rejects_invalid_claims_and_signature() {
        for change in [
            json!({"version": 1}),
            json!({"version": 2}),
            json!({"iss": "other"}),
            json!({"nbf": 160}),
            json!({"exp": 150}),
            json!({"fingerprintSha256": "other"}),
            json!({"entitlements": [{"code": "  ", "name": "功能A"}]}),
            json!({"licenseKey": "   "}),
            json!({"iat": 300}),
        ] {
            let (token, key) = signed_token(change);
            assert!(verify_certificate(&token, &[key], "issuer", "fingerprint", 150).is_err());
        }
        let (mut token, key) = signed_token(json!({}));
        token.push('x');
        assert!(verify_certificate(&token, &[key], "issuer", "fingerprint", 150).is_err());
    }

    #[test]
    fn rejects_unknown_key_and_bad_format() {
        let (token, _) = signed_token(json!({}));
        assert!(matches!(
            verify_certificate(&token, &[], "issuer", "fingerprint", 150),
            Err(LicenseError::SigningKeyMissing)
        ));
        assert!(matches!(
            verify_certificate("not-a-token", &[], "issuer", "fingerprint", 150),
            Err(LicenseError::TokenFormat)
        ));
    }

    #[test]
    fn environment_without_activation_is_not_activated() {
        let temp = tempfile::tempdir().unwrap();
        let environment = LicenseEnvironment::open(temp.path().join("test.db")).unwrap();
        assert!(verify_environment(&environment, "issuer").unwrap().is_none());
    }

    #[test]
    fn environment_with_valid_license_verifies() {
        let temp = tempfile::tempdir().unwrap();
        let environment = LicenseEnvironment::open(temp.path().join("test.db")).unwrap();
        let fingerprint = fingerprint::current_fingerprint().unwrap();
        let now = now_epoch();
        let (token, key) = signed_token(json!({
            "fingerprintSha256": fingerprint,
            "iat": now - 10, "nbf": now - 10, "exp": now + 3600
        }));
        environment.save_keys(&[key]).unwrap();
        environment
            .save_activation(&StoredLicense {
                token,
                source: ActivationSource::Online,
                activated_at: now_epoch(),
            })
            .unwrap();

        let verified = verify_environment(&environment, "issuer")
            .unwrap()
            .expect("valid license must verify");
        assert_eq!(verified.claims.license_key, "LIC-TEST");
        assert_eq!(verified.claims.product_name, "产品");
        assert_eq!(verified.fingerprint, fingerprint);
        assert_eq!(verified.source, ActivationSource::Online);
    }

    #[test]
    fn environment_with_tampered_license_fails_and_keeps_token() {
        let temp = tempfile::tempdir().unwrap();
        let environment = LicenseEnvironment::open(temp.path().join("test.db")).unwrap();
        let fingerprint = fingerprint::current_fingerprint().unwrap();
        let now = now_epoch();
        let (token, key) = signed_token(json!({
            "fingerprintSha256": fingerprint,
            "iat": now - 10, "nbf": now - 10, "exp": now + 3600
        }));
        // 等长篡改签名末字符，触发验签失败而非格式错误
        let flipped = if token.ends_with('A') { 'B' } else { 'A' };
        let token = format!("{}{flipped}", &token[..token.len() - 1]);
        environment.save_keys(&[key]).unwrap();
        environment
            .save_activation(&StoredLicense {
                token,
                source: ActivationSource::Offline,
                activated_at: now_epoch(),
            })
            .unwrap();

        assert!(matches!(
            verify_environment(&environment, "issuer"),
            Err(LicenseError::Signature)
        ));
        // SDK 不清除令牌，清理由激活入口负责
        assert!(environment.load_activation().unwrap().is_some());
    }
}
