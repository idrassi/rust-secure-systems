use std::env;
use std::fs::File;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("secret `{0}` not found")]
    NotFound(String),

    #[error("secret is not valid hex")]
    InvalidFormat,

    #[error("insecure permissions on `{path}`: {mode}")]
    InsecurePermissions { path: String, mode: String },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("vault error: {0}")]
    VaultError(String),
}

pub fn decode_secret_value(mut value: String) -> Result<Vec<u8>, SecretError> {
    let decoded = hex::decode(&value).map_err(|_| SecretError::InvalidFormat);
    value.zeroize();
    decoded
}

pub fn load_secret(key: &str) -> Result<Vec<u8>, SecretError> {
    let value = env::var(key).map_err(|_| SecretError::NotFound(key.to_string()))?;
    decode_secret_value(value)
}

pub fn load_secret_from_file(path: &str) -> Result<Vec<u8>, SecretError> {
    let mut file = File::open(path)?;

    #[cfg(unix)]
    {
        // Inspect the same opened file handle we will read from to avoid a
        // path-swap race between validation and use.
        let metadata = file.metadata()?;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(SecretError::InsecurePermissions {
                path: path.to_string(),
                mode: format!("{:o}", mode & 0o777),
            });
        }
    }

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}
