use std::string::FromUtf8Error;
use tracing::error;

use aes_gcm::{
    AeadCore, Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, consts::U32, generic_array::GenericArray},
};
use base64::{Engine, engine::general_purpose};
use thiserror::Error;

#[derive(Debug, Clone, Copy)]
pub struct AesGcmCryptographer {
    pub key: GenericArray<u8, U32>,
}

#[derive(Debug, Error)]
pub enum AesGcmCryptographerError {
    #[error("Aes Gcm error: {0}")]
    AesGcm(String),

    #[error("From Utf8 convert error: {0}")]
    FromUtf8(#[from] FromUtf8Error),

    #[error("Base64 deocde error: {0}")]
    Base64Decode(#[from] base64::DecodeError),
}

impl From<aes_gcm::Error> for AesGcmCryptographerError {
    fn from(value: aes_gcm::Error) -> Self {
        AesGcmCryptographerError::AesGcm(value.to_string())
    }
}

impl AesGcmCryptographer {
    pub fn new(key: &GenericArray<u8, U32>) -> Self {
        Self { key: *key }
    }

    pub fn encrypt(&self, data: &str) -> Result<(String, String), AesGcmCryptographerError> {
        let cipher = Aes256Gcm::new(&self.key);

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let encrypted = cipher
            .encrypt(&nonce, data.as_bytes().as_ref())
            .map_err(|error| match error {
                _ => {
                    error!("{}", error);
                    error
                }
            })?;

        Ok((
            general_purpose::STANDARD.encode(encrypted),
            general_purpose::STANDARD.encode(nonce.to_vec()),
        ))
    }

    pub fn decrypt(
        &self,
        encrypted: &str,
        nonce: &str,
    ) -> Result<String, AesGcmCryptographerError> {
        let encrypted =
            general_purpose::STANDARD
                .decode(encrypted)
                .map_err(|error| match error {
                    _ => {
                        error!("{}", error);
                        error
                    }
                })?;
        let nonce = general_purpose::STANDARD
            .decode(nonce)
            .map_err(|error| match error {
                _ => {
                    error!("{}", error);
                    error
                }
            })?;

        let cipher = Aes256Gcm::new(&self.key);

        let nonce = Nonce::from_slice(&nonce);

        let decrypted =
            cipher
                .decrypt(&nonce, encrypted.as_ref())
                .map_err(|error| match error {
                    _ => {
                        error!("{}", error);
                        error
                    }
                })?;

        Ok(String::from_utf8(decrypted).map_err(|error| match error {
            _ => {
                error!("{}", error);
                error
            }
        })?)
    }
}
