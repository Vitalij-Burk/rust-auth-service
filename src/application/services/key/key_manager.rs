use std::{
    path::PathBuf,
    string::FromUtf8Error,
};

use thiserror::Error;
use tracing::error;

use crate::infrastructure::{
    key::pem::rsa::rsa_provider::RsaPemProvider, utils::io::files::files_io::FileIO,
};

#[derive(Debug, Clone)]
pub struct KeyManager {
    pub key_provider: RsaPemProvider,
    pub keys_dir: PathBuf,
    pub private_pem_file_io: FileIO,
    pub public_pem_file_io: FileIO,
}

#[derive(Debug, Error)]
pub enum KeyManagerError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Already exists: {0}")]
    AlreadyExists(String),

    #[error("Unexpected error: {0}")]
    Unexpected(String),

    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),

    #[error("From UTF-8 error: {0}")]
    FromUTF8(#[from] FromUtf8Error),
}

impl KeyManager {
    pub fn new(keys_dir_path: &str) -> Result<Self, KeyManagerError> {
        let keys_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(keys_dir_path);

        if !keys_dir.exists() {
            let _ = std::fs::create_dir(&keys_dir).map_err(|error| match error {
                err => {
                    error!("Couldn't create keys directory: {}", &err);
                    err
                }
            });
        }

        let private_pem_file_io = FileIO::new(
            keys_dir
                .join("private.pem")
                .to_str()
                .ok_or(KeyManagerError::Unexpected("Invalid path".to_string()))?,
        );
        let public_pem_file_io = FileIO::new(
            keys_dir
                .join("public.pem")
                .to_str()
                .ok_or(KeyManagerError::Unexpected("Invalid path".to_string()))?,
        );

        Ok(Self {
            key_provider: RsaPemProvider,
            keys_dir: keys_dir,
            private_pem_file_io: private_pem_file_io,
            public_pem_file_io: public_pem_file_io
        })
    }

    pub fn provide(&self) -> Result<(), KeyManagerError> {
        let (private_pem, public_pem) = self.key_provider.generate_pair();

        self.private_pem_file_io.write(&private_pem)?;
        self.public_pem_file_io.write(&public_pem)?;

        Ok(())
    }

    pub fn rollback(&self) -> Result<(), KeyManagerError> {
        self.private_pem_file_io.remove()?;
        self.public_pem_file_io.remove()?;

        Ok(())
    }

    pub fn update(&self) -> Result<(), KeyManagerError> {
        let (private_pem, public_pem) = self.key_provider.generate_pair();

        self.private_pem_file_io.remove()?;
        self.public_pem_file_io.remove()?;

        self.private_pem_file_io.write(&private_pem)?;
        self.public_pem_file_io.write(&public_pem)?;

        Ok(())
    }

    pub fn get_public(&self) -> Result<String, KeyManagerError> {
        let public_pem = String::from_utf8(self.public_pem_file_io.read()?)
        .map_err(|error| match error {
            err => {
                error!("From UTF-8 error caused: {}", &err);
                err
            }
        })?;

        Ok(public_pem)
    }

    pub fn get_private(&self) -> Result<String, KeyManagerError> {
        let private_pem = String::from_utf8(self.private_pem_file_io.read()?)
        .map_err(|error| match error {
            err => {
                error!("From UTF-8 error caused: {}", &err);
                err
            }
        })?;

        Ok(private_pem)
    }
}
