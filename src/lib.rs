//! License Rust SDK：从本地环境读取离线令牌并完成校验。
//!
//! 环境库由 license-active 激活入口写入（路径、格式见 [`LicenseEnvironment`]），
//! 其它客户端通过 [`verify_environment`] 离线判断当前环境是否已获得许可。
//! 需要自定义校验（如指定时间、外部密钥）时可使用 [`verify_certificate`] 原语。

mod claims;
mod environment;
mod error;
mod fingerprint;
mod verifier;

pub use claims::{
    ActivationSource, Claims, EntitlementClaim, PublicJwk, StoredLicense, VerifiedLicense,
};
pub use environment::LicenseEnvironment;
pub use error::LicenseError;
pub use fingerprint::current_fingerprint;
pub use verifier::{verify_certificate, verify_environment};
