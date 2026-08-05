use std::fs;

use license_sdk::VerifyError;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TTSConstraint {
    pub max_version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Meta {
    #[serde(rename = "TTS")]
    pub tts: TTSConstraint,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 获取公钥和证书内容，注意公钥只能使用硬编码或者预编译宏将其导入，不能在运行时读取，否则会被篡改。
    let key = include_str!("./key/key.pub");
    let certification = fs::read_to_string("./examples/licenses/2026-08-05.lic")?;

    // 获取设备指纹
    let fingerprint = license_sdk::read_machine_guid()?;
    println!("设备指纹: {}", fingerprint);

    // 创建验证器, decoding_key必填，fingerprint，product_code，user_id需要时选填，目前不处理product_code和user_id。
    let verifier = license_sdk::VerifierBuilder::new()
        .decoding_key(key)?
        .fingerprint("123456") //此处应替换为fingerprint
        .build();

    // 验证证书，泛型参数用于客户端指定所需的数据
    let result = verifier.verify::<Meta>(&certification);
    // 错误处理，可以按需处理
    if let Err(err) = &result {
        match err {
            VerifyError::InvalidCertificate(msg) => {
                println!("无效证书: {}", msg);
            }
            VerifyError::FingerprintMismatch => {
                println!("指纹不匹配");
            }
            VerifyError::LicenseExpired(stamp) => {
                println!("证书已过期: {}", stamp);
            }
            VerifyError::LicenseTampered => {
                println!("证书被篡改");
            }
            VerifyError::DecodingKeyMismatch(kid) => {
                println!("解码密钥不匹配: {}", kid);
            }
            _ => {
                println!("其他错误: {:?}", err);
            }
        }
    }

    // 证书中保存的数据，claims.entitlements是允许使用的模块ID列表，claims.meta是自定义数据，客户端可根据需要定义结构体。
    let claims = result.unwrap();
    println!("证书验证成功，claims: {:?}", claims);

    Ok(())
}
