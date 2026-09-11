use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LicenseError {
    #[error("无法访问本地许可环境: {0}")]
    Environment(String),

    #[error("本地许可数据读写失败: {0}")]
    Storage(String),

    #[error("本地许可未激活")]
    Inactive,

    #[error("设备指纹计算失败: {0}")]
    Fingerprint(String),

    #[error("令牌格式不正确")]
    TokenFormat,

    #[error("令牌算法或类型不受支持")]
    TokenAlgorithm,

    #[error("找不到令牌对应的签名公钥")]
    SigningKeyMissing,

    #[error("签名公钥无效: {0}")]
    SigningKeyInvalid(String),

    #[error("令牌内容无效")]
    TokenPayload,

    #[error("签名验证失败")]
    Signature,

    #[error("令牌版本不受支持")]
    Version,

    #[error("令牌缺少必要声明")]
    MissingClaims,

    #[error("令牌授权项无效")]
    Entitlements,

    #[error("令牌尚未生效")]
    NotYetValid,

    #[error("令牌已过期")]
    Expired,

    #[error("令牌时间范围无效")]
    TimeRange,

    #[error("令牌不属于当前设备")]
    FingerprintMismatch,
}
