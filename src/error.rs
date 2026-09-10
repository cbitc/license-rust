use thiserror::Error;

/// SDK 统一错误。令牌类变体的消息与 license-active 的本地校验保持一致，
/// 便于将来激活入口迁移到本 SDK 时映射无损。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LicenseError {
    /// 无法确定或打开本地环境数据（数据目录、数据库文件）。
    #[error("无法访问本地许可环境: {0}")]
    Environment(String),

    /// 本地数据库读写失败。
    #[error("本地许可数据读写失败: {0}")]
    Storage(String),

    /// 设备指纹计算失败（如无法获取主机名）。
    #[error("设备指纹计算失败: {0}")]
    Fingerprint(String),

    /// 令牌不是合法的三段式 JWS。
    #[error("令牌格式不正确")]
    TokenFormat,

    /// 令牌头部的算法或类型不受支持。
    #[error("令牌算法或类型不受支持")]
    TokenAlgorithm,

    /// 找不到令牌 kid 对应的签名公钥。
    #[error("找不到令牌对应的签名公钥")]
    SigningKeyMissing,

    /// 签名公钥类型、编码或长度无效。
    #[error("签名公钥无效: {0}")]
    SigningKeyInvalid(String),

    /// 令牌 payload 无法解码为 v3 claims。
    #[error("令牌内容无效")]
    TokenPayload,

    /// Ed25519 签名验证失败。
    #[error("签名验证失败")]
    Signature,

    /// 令牌版本不受支持（当前仅支持 version 3）。
    #[error("令牌版本不受支持")]
    Version,

    /// 令牌签发方与预期不符。
    #[error("令牌签发方不匹配")]
    Issuer,

    /// 令牌缺少必要声明。
    #[error("令牌缺少必要声明")]
    MissingClaims,

    /// 令牌授权项无效（存在空白 code）。
    #[error("令牌授权项无效")]
    Entitlements,

    /// 令牌尚未到生效时间。
    #[error("令牌尚未生效")]
    NotYetValid,

    /// 令牌已过期。
    #[error("令牌已过期")]
    Expired,

    /// 令牌声明的时间范围自相矛盾。
    #[error("令牌时间范围无效")]
    TimeRange,

    /// 令牌绑定的设备指纹与当前环境不符。
    #[error("令牌不属于当前设备")]
    FingerprintMismatch,
}
