use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    // 密钥不合法
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),

    // 许可证被篡改
    #[error("License tampered")]
    LicenseTampered,

    #[error("key Mismatch: {0}")]
    DecodingKeyMismatch(String),

    // 许可证过期
    #[error("License expired at {0}")]
    LicenseExpired(i64),

    // 指纹不匹配
    #[error("Fingerprint mismatch")]
    FingerprintMismatch,

    // meta字段解析错误
    #[error("Failed to parse meta field: {0}")]
    MetaParseError(String),

    // sdk内部错误
    #[error("Internal error: {0}")]
    InternalError(String),
}
