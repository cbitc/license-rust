# license-sdk

用于本地软件离线授权校验的 Rust SDK。客户端内置公钥和许可证文件，在离线情况下验证许可证签名、有效期、设备指纹以及授权功能列表。

## 安装
需要依赖serde反序列
在应用的 `Cargo.toml` 中添加：

```toml
[dependencies]
serde = { version = "1", features = ["derive"] }
license-sdk = { git = "http://192.168.1.252:3000/cbitc/license-sdk-rust.git", tag = "v0.1.0" }
```

## 快速开始

下面的示例使用仓库中的公钥和许可证文件。

```rust
use license_sdk::{VerifierBuilder, VerifyError};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TtsConstraint {
    max_version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LicenseMeta {
    #[serde(rename = "TTS")]
    tts: TtsConstraint,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 获取公钥和证书内容，注意公钥只能使用硬编码或者预编译宏将其导入，不能在运行时读取，否则会被篡改。
    let key = include_str!("../examples/key/key.pub");
    let license = fs::read_to_string("./examples/licenses/2026-08-05.lic")?;

    let verifier = VerifierBuilder::new()
        .decoding_key(key)?
        .fingerprint("123456") // 此处替换为guid
        .build();

    let claims = verifier.verify::<LicenseMeta>(license).map_err(|error| {
        match &error {
            VerifyError::InvalidCertificate(message) => {
                eprintln!("许可证格式无效: {message}");
            }
            VerifyError::LicenseTampered => {
                eprintln!("许可证签名校验失败，文件可能被篡改");
            }
            VerifyError::DecodingKeyMismatch(kid) => {
                eprintln!("许可证 kid 与内置公钥不匹配: {kid}");
            }
            VerifyError::LicenseExpired(timestamp) => {
                eprintln!("许可证已于 Unix 时间 {timestamp} 到期");
            }
            VerifyError::FingerprintMismatch => {
                eprintln!("设备指纹不匹配");
            }
            VerifyError::MetaParseError(message) => {
                eprintln!("meta 字段解析失败: {message}");
            }
            other => eprintln!("许可证校验失败: {other}"),
        }
        error
    })?;

    println!("授权功能: {:?}", claims.entitlements);
    println!("TTS 最高版本: {}", claims.meta.tts.max_version);
    Ok(())
}
```

如果要使用当前 Windows 设备指纹，请将示例中的固定值替换为：

```rust
let fingerprint = license_sdk::read_machine_guid()?;
let verifier = VerifierBuilder::new()
    .decoding_key(key)?
    .fingerprint(&fingerprint)
    .build();
```

`read_machine_guid()` 会读取 `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`，非 Windows 平台调用该函数会返回错误。

## API 参考

### `VerifierBuilder`

| 方法 | 说明 |
| --- | --- |
| `VerifierBuilder::new()` | 创建未配置公钥的构建器。也可使用 `Default::default()`。 |
| `.decoding_key(key)` | 解析Base64 编码的 JWK。参数是 `&'static str`，返回 `Result`。这是必填配置。 |
| `.fingerprint(value)` | 设置客户端设备指纹。用于与许可证也包含的绑定指纹比较进行比较。 |
| `.user_id(value)` | 保存许可证持有人标识。当前版本不会使用该值参与校验。 |
| `.product_code(value)` | 保存产品标识。当前版本不会使用该值参与校验。 |

### `Verifier::verify`

```rust
pub fn verify<T>(&self, certificate: &str) -> Result<Claims<T>, VerifyError>
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de>;
```

`T` 是应用为许可证 `meta` 字段定义的类型。成功结果包含：

- `claims.entitlements: Vec<String>`：许可证允许使用的功能代码列表。
- `claims.meta: T`：反序列化后的自定义数据。

### `read_machine_guid`

```rust
pub fn read_machine_guid() -> Result<String, String>
```

仅 Windows 实现会读取系统注册表中的 `MachineGuid`；其他平台返回“测试客户端仅支持 Windows”错误。

### `VerifyError`

| 错误 | 含义 |
| --- | --- |
| `InvalidKey(message)` | 公钥不是合法 Base64/JWK，或不属于内部发行的密钥 |
| `InvalidCertificate(message)` | 许可证格式不符合要求。 |
| `LicenseTampered` | 签名校验失败，许可文件被篡改 |
| `DecodingKeyMismatch(kid)` | 许可证要求的密钥与内置公钥不一致。 |
| `LicenseExpired(timestamp)` | ttl过期，单位是unix timestamp seconds。 |
| `FingerprintMismatch` | 设备指纹与许可证不一致。 |
| `MetaParseError(message)` | `meta` 无法反序列化为调用方指定的类型，来源于客户端错误 |
| `InternalError(message)` | SDK 内部错误。 |

## 安全建议

- 使用 `include_str!` 或其他编译期方式嵌入公钥；不要在运行时读取文件。
- 离线校验依赖客户端系统时钟和本地运行环境。但 SDK 只验证签名完整性和许可证规则，无法保证客户端环境不被篡改。

## 公钥和license获取
以下的获取流程仅用于测试

当前用于测试公钥为： "eyJjcnYiOiJFZDI1NTE5IiwieCI6IlNkUWI5ZDQtTVctck05MUVVVXJIRW5WaHYzLU1meXltWDBvX2NXYzNVWGsiLCJrdHkiOiJPS1AiLCJraWQiOiIyMDI2LjA4LjA1IiwiYWxnIjoiRWREU0EiLCJ1c2UiOiJzaWcifQ"

license: 访问http://139.199.182.155，登录token为1111111122222222。
操作：
1. 创建所需的产品，功能权限和许可策略。
2. 新建许可证：选择许可策略后创建许可证，（license-key 是分发至用户用以更换，续签的凭证，当前可忽略）
3. 离线签发：选择许可证后点击签发离线许可。

提示:
当前若并不使用产品参与校验，可以使用产品“ANY”来表示一种逻辑上的包含所有产品的产品来实现，然后将许可策略设置为永不过期，各个模块分别过期就可以实现一种分模块不分产品的效果。