use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Claims {
    pub version: u8,
    #[serde(default)]
    pub meta: serde_json::Value,
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub jti: String,
    pub policy_id: String,
    #[serde(default)]
    pub user_id: Option<String>,
    pub license_key: String,
    pub product_code: String,
    pub product_name: String,
    pub policy_name: String,
    pub issued_at: i64,
    pub entitlements: Vec<EntitlementClaim>,
    #[serde(default)]
    pub fingerprint_sha256: Option<String>,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    #[serde(default)]
    pub license_expires_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitlementClaim {
    pub code: String,
    pub name: String,
    #[serde(default)]
    pub expires_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub kid: String,
    pub alg: Option<String>,
    #[serde(rename = "use")]
    pub key_use: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationSource {
    Online,
    Offline,
}

/// 持久化在本地环境中的唯一数据：令牌本体 + 两个客户端本地事实。
/// claims 等派生信息在运行时从令牌新鲜解析，不落库。
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StoredLicense {
    pub token: String,
    pub source: ActivationSource,
    pub activated_at: i64,
}

/// 环境校验通过后的运行时视图。
#[derive(Clone, Debug)]
pub struct VerifiedLicense {
    pub token: String,
    pub source: ActivationSource,
    pub activated_at: i64,
    pub claims: Claims,
    /// 校验时使用的当前设备指纹。
    pub fingerprint: String,
}

impl From<(&StoredLicense, Claims, String)> for VerifiedLicense {
    fn from((stored, claims, fingerprint): (&StoredLicense, Claims, String)) -> Self {
        Self {
            token: stored.token.clone(),
            source: stored.source,
            activated_at: stored.activated_at,
            claims,
            fingerprint,
        }
    }
}
