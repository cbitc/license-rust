use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Claims<T: Serialize> {
    pub entitlements: Vec<String>,
    pub meta: T,
}

impl<T: Serialize> Claims<T> {
    pub fn new(entitlements: Vec<String>, meta: T) -> Self {
        Self { entitlements, meta }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OfflineValidation {
    pub version: u8,
    pub meta: Value,
    /// 服务端签发者标识。
    pub iss: String,
    /// Product UUID。
    pub aud: String,
    /// License UUID。
    pub sub: String,
    /// LicenseIssuance UUID。
    pub jti: String,
    /// Policy UUID。
    pub policy_id: String,
    /// 可选许可证持有人 UUID
    #[serde(default)]
    pub user_id: Option<String>,
    /// 签发时的功能代码
    pub entitlements: Vec<String>,
    #[serde(default)]
    pub fingerprint_sha256: Option<String>,
    /// 签发时间 Unix 秒。
    pub iat: i64,
    /// 最早生效时间 Unix 秒。
    pub nbf: i64,
    /// 离线文件到期时间 Unix 秒。
    pub exp: i64,
    #[serde(default)]
    pub license_expires_at: Option<i64>,
}
