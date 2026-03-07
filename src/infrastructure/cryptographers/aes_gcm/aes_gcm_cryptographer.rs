use aes_gcm::{
    AeadCore, Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, consts::U32, generic_array::GenericArray},
};
use base64::{Engine, engine::general_purpose};

#[derive(Debug, Clone, Copy)]
pub struct AesGcmCryptographer {
    pub key: GenericArray<u8, U32>,
}

impl AesGcmCryptographer {
    pub fn new(key: &GenericArray<u8, U32>) -> Self {
        Self { key: *key }
    }

    pub fn encrypt(&self, data: &str) -> Result<(String, String), aes_gcm::Error> {
        let cipher = Aes256Gcm::new(&self.key);

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let encrypted = cipher.encrypt(&nonce, data.as_bytes().as_ref())?;

        Ok((general_purpose::STANDARD.encode(encrypted), general_purpose::STANDARD.encode(nonce.to_vec())))
    }

    pub fn decrypt(&self, encrypted: &str, nonce: &str) -> Result<String, aes_gcm::Error> {
        let encrypted = general_purpose::STANDARD.decode(encrypted).unwrap();
        let nonce = general_purpose::STANDARD.decode(nonce).unwrap();

        let cipher = Aes256Gcm::new(&self.key);

        let nonce = Nonce::from_slice(&nonce);

        let decrypted = cipher.decrypt(&nonce, encrypted.as_ref())?;

        Ok(String::from_utf8(decrypted).unwrap())
    }
}
