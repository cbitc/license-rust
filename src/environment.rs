use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use rusqlite::Connection;

use crate::{
    claims::{PublicJwk, StoredLicense},
    error::LicenseError,
};

/// 与 license-active 内置的信任公钥一致（kid 2026.08.05）。
/// 校验时与本地缓存公钥按 kid 合并（缓存优先），保证全新环境也能验证由该密钥签发的令牌。


/// 本地许可环境：license-active 写入、各客户端共享读取的 SQLite 库。
///
/// 路径与表结构和 license-active 完全一致
/// （`ProjectDirs::from("com","license-tools","license-active").data_local_dir()/license.db`）。
#[derive(Clone, Debug)]
pub struct LicenseEnvironment {
    path: PathBuf,
}

impl LicenseEnvironment {
    /// 打开默认共享环境（license-active 使用的同一路径）。
    pub fn open_default() -> Result<Self, LicenseError> {
        Self::open(default_environment_path()?)
    }

    /// 打开指定路径的环境库（会按需创建目录、数据表）。
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LicenseError> {
        let environment = Self {
            path: path.as_ref().to_owned(),
        };
        if let Some(parent) = environment.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| LicenseError::Environment(error.to_string()))?;
        }
        environment.with_connection(|connection| {
            connection
                .execute_batch(
                    "PRAGMA journal_mode=WAL;
                     PRAGMA foreign_keys=ON;
                     CREATE TABLE IF NOT EXISTS signing_keys (
                        kid TEXT PRIMARY KEY,
                        jwk_json TEXT NOT NULL,
                        updated_at INTEGER NOT NULL
                     );
                     CREATE TABLE IF NOT EXISTS activation (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        activation_json TEXT NOT NULL
                     );",
                )
                .map_err(|error| LicenseError::Storage(error.to_string()))?;
            Ok(())
        })?;
        Ok(environment)
    }

    /// 读取当前激活记录（仅令牌本体与两个本地事实，claims 需校验后从令牌解析）。
    pub fn load_activation(&self) -> Result<Option<StoredLicense>, LicenseError> {
        self.with_connection(|connection| {
            let mut statement = connection
                .prepare("SELECT activation_json FROM activation WHERE id = 1")
                .map_err(|error| LicenseError::Storage(error.to_string()))?;
            let mut rows = statement
                .query([])
                .map_err(|error| LicenseError::Storage(error.to_string()))?;
            match rows
                .next()
                .map_err(|error| LicenseError::Storage(error.to_string()))?
            {
                Some(row) => {
                    let json: String = row
                        .get(0)
                        .map_err(|error| LicenseError::Storage(error.to_string()))?;
                    serde_json::from_str(&json)
                        .map_err(|error| LicenseError::Storage(error.to_string()))
                }
                None => Ok(None),
            }
        })
    }

    /// 读取本地缓存的签名公钥（不含内置公钥；校验入口会自动合并）。
    pub fn load_keys(&self) -> Result<Vec<PublicJwk>, LicenseError> {
        self.with_connection(|connection| {
            let mut statement = connection
                .prepare("SELECT jwk_json FROM signing_keys")
                .map_err(|error| LicenseError::Storage(error.to_string()))?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|error| LicenseError::Storage(error.to_string()))?;
            let mut keys = Vec::new();
            for row in rows {
                let json = row.map_err(|error| LicenseError::Storage(error.to_string()))?;
                let key: PublicJwk = serde_json::from_str(&json)
                    .map_err(|error| LicenseError::Storage(error.to_string()))?;
                keys.push(key);
            }
            Ok(keys)
        })
    }

    fn with_connection<T>(
        &self,
        operation: impl FnOnce(&Connection) -> Result<T, LicenseError>,
    ) -> Result<T, LicenseError> {
        let connection = Connection::open(&self.path)
            .map_err(|error| LicenseError::Environment(error.to_string()))?;
        connection
            .busy_timeout(std::time::Duration::from_secs(3))
            .map_err(|error| LicenseError::Storage(error.to_string()))?;
        operation(&connection)
    }
}

fn default_environment_path() -> Result<PathBuf, LicenseError> {
    let project_dirs = ProjectDirs::from("com", "license-tools", "license-active")
        .ok_or_else(|| LicenseError::Environment("无法确定应用数据目录".to_owned()))?;
    Ok(project_dirs.data_local_dir().join("license.db"))
}

#[cfg(test)]
mod tests {}
