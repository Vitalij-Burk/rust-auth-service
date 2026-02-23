use std::{
    fs::{create_dir, read, remove_file, write},
    path::PathBuf,
};

use thiserror::Error;

use crate::infrastructure::key::pem::rsa::rsa_provider::RsaPemProvider;

#[derive(Debug, Clone)]
pub struct KeyManager {
    pub key_provider: RsaPemProvider,
    pub keys_dir: PathBuf,
}

#[derive(Debug, Error)]
pub enum KeyManagerError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Already exists: {0}")]
    AlreadyExists(String),
}

impl KeyManager {
    pub fn new(keys_dir_path: &str) -> Self {
        let keys_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(keys_dir_path);

        {
            if keys_dir.exists() {

            } else {
                create_dir(&keys_dir).unwrap();
            }
        }

        Self {
            key_provider: RsaPemProvider,
            keys_dir: keys_dir,
        }
    }

    pub fn provide(&self) -> Result<(), KeyManagerError> {
        let (private_pem, public_pem) = self.key_provider.generate_pair();

        {
            if self.keys_dir.join("private.pem").exists() {
                return Ok(())
            }
            if self.keys_dir.join("public.pem").exists() {
                return Ok(())
            }
        }

        {
            let _ = write(self.keys_dir.join("private.pem"), private_pem);
            let _ = write(self.keys_dir.join("public.pem"), public_pem);
        }

        Ok(())
    }

    pub fn rollback(&self) {
        {
            let _ = remove_file(self.keys_dir.join("private.pem"));
            let _ = remove_file(self.keys_dir.join("public.pem"));
        }
    }

    pub fn update(&self) {
        let (private_pem, public_pem) = self.key_provider.generate_pair();

        {
            let _ = remove_file(self.keys_dir.join("private.pem"));
            let _ = remove_file(self.keys_dir.join("public.pem"));
        }
        {
            let _ = write(self.keys_dir.join("private.pem"), private_pem);
            let _ = write(self.keys_dir.join("public.pem"), public_pem);
        }
    }

    pub fn get_public(&self) -> Result<String, Box<dyn std::error::Error>> {
        let public_pem =
            String::from_utf8(read(self.keys_dir.join("public.pem")).unwrap()).unwrap();

        Ok(public_pem)
    }

    pub fn get_private(&self) -> Result<String, Box<dyn std::error::Error>> {
        let private_pem =
            String::from_utf8(read(self.keys_dir.join("private.pem")).unwrap()).unwrap();

        Ok(private_pem)
    }
}
