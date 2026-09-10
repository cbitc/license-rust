use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use rusqlite::Connection;

use crate::{claims::StoredLicense, error::LicenseError};

#[derive(Clone, Debug)]
pub struct LicenseEnvironment {
    path: PathBuf,
}

impl LicenseEnvironment {
    pub fn open_default() -> Result<Self, LicenseError> {
        Self::open(default_environment_path()?)
    }

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
