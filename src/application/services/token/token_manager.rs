use aes_gcm::{
    Aes256Gcm,
    aead::{KeyInit, OsRng},
};
use base64::{self, Engine, engine::general_purpose};
use std::{path::PathBuf, string::FromUtf8Error};
use tracing::error;

use thiserror::Error;

use crate::{
    domain::{
        models::claims::Claims,
        traits::token::{
            jwt::{token_provider::IJwtTokenProvider, token_validator::IJwtTokenValidator},
            opaque::token_provider::IOpaqueTokenProvider,
        },
    },
    infrastructure::{
        cryptographers::aes_gcm::aes_gcm_cryptographer::{
            AesGcmCryptographer, AesGcmCryptographerError,
        },
        storage::redis::io::redis_io::RedisIO,
        token::jwks::{
            jwks_provider::JwksTokenProviderError, jwks_validator::JwksTokenValidatorError,
        },
        utils::io::files::files_io::FileIO,
    },
};

#[derive(Debug, Clone)]
pub struct TokenManager<AccessProvider, AccessValidator, RefreshProvider, Storage> {
    pub access_provider: AccessProvider,
    pub access_validator: AccessValidator,
    pub refresh_provider: RefreshProvider,
    pub cryptographer: AesGcmCryptographer,
    pub keys_dir: PathBuf,
    pub redis_io: RedisIO<Storage>,
}

#[derive(Debug, Error)]
pub enum TokenManagerError {
    #[error("Jwks provider error: {0}")]
    JwksTokenProvider(#[from] JwksTokenProviderError),

    #[error("Jwks validator error: {0}")]
    JwksTokenValidator(#[from] JwksTokenValidatorError),

    #[error("Redis storage error: {0}")]
    RedisError(#[from] redis::RedisError),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("From UTF-8 error: {0}")]
    FromUTF8(#[from] FromUtf8Error),

    #[error("Unexpected error: {0}")]
    Unexpected(String),

    #[error("Cryptographer error: {0}")]
    Cryptographer(#[from] AesGcmCryptographerError),
}

impl<AccessProvider, AccessValidator, RefreshProvider, Storage>
    TokenManager<AccessProvider, AccessValidator, RefreshProvider, Storage>
where
    AccessProvider: IJwtTokenProvider<Claims = Claims, Error = JwksTokenProviderError>,
    AccessValidator: IJwtTokenValidator<Claims = Claims, Error = JwksTokenValidatorError>,
    RefreshProvider: IOpaqueTokenProvider,
    Storage: redis::AsyncCommands + Send + Sync,
{
    pub fn new(
        access_provider: AccessProvider,
        access_validator: AccessValidator,
        refresh_provider: RefreshProvider,
        keys_dir_path: &str,
        storage: Storage,
    ) -> Result<Self, TokenManagerError> {
        let redis_io = RedisIO::new(storage);

        let keys_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(keys_dir_path);

        if !keys_dir.exists() {
            let _ = std::fs::create_dir(&keys_dir).map_err(|error| match error {
                err => {
                    error!("Couldn't create keys directory: {}", &err);
                    err
                }
            });
        }

        let encryption_key_file_io = FileIO::new(
            keys_dir
                .join("encryption_key.txt")
                .to_str()
                .ok_or(TokenManagerError::Unexpected("Invalid path".to_string()))?,
        );

        let key = Aes256Gcm::generate_key(OsRng);

        let base64_key = general_purpose::STANDARD.encode(key.as_slice());

        let _ = encryption_key_file_io.write(&base64_key);

        let cryptographer = AesGcmCryptographer::new(&key);

        Ok(Self {
            access_provider,
            access_validator,
            refresh_provider,
            redis_io,
            cryptographer,
            keys_dir,
        })
    }

    pub async fn generate_pair(
        &mut self,
        claims: &Claims,
        pem: &str,
    ) -> Result<(String, (String, String)), TokenManagerError> {
        let access_token = self.access_provider.generate(&claims, &pem)?;
        let refresh_token = self.refresh_provider.generate();

        let refresh_to_exp_sec = 60 * 60 * 24 * 7;

        self.redis_io
            .setex(
                &format!("tokens:refresh:token:{}", &refresh_token),
                "exists",
                refresh_to_exp_sec,
            )
            .await?;

        println!("Service before cryptography");

        let (encrypted_refresh, nonce) = self.cryptographer.encrypt(&refresh_token)?;

        println!("Service after cryptography");

        Ok((access_token, (encrypted_refresh, nonce)))
    }

    pub async fn verify_access(
        &mut self,
        access: &str,
        pem: &str,
    ) -> Result<Claims, TokenManagerError> {
        let claims = self.access_validator.verify(access, pem)?;

        Ok(claims)
    }

    pub async fn verify_refresh(
        &mut self,
        encrypted_refresh: &str,
        nonce: &str,
    ) -> Result<(), TokenManagerError> {
        let refresh = self.cryptographer.decrypt(&encrypted_refresh, &nonce)?;

        let refresh_token = self
            .redis_io
            .get(&format!("tokens:refresh:token:{}", &refresh.clone()))
            .await?;

        if refresh_token.is_empty() {
            return Err(TokenManagerError::NotFound(format!(
                "Refresh token {} not found",
                &refresh.clone()
            )));
        }

        Ok(())
    }

    pub async fn revoke_refresh(
        &mut self,
        encrypted_refresh: &str,
        nonce: &str,
    ) -> Result<(), TokenManagerError> {
        let refresh = self.cryptographer.decrypt(&encrypted_refresh, &nonce)?;

        self.redis_io
            .delete(&format!("tokens:refresh:token:{}", &refresh))
            .await?;

        Ok(())
    }

    pub async fn refresh(
        &mut self,
        encrypted_refresh: &str,
        nonce: &str,
        access: &str,
        private_pem: &str,
        public_pem: &str,
    ) -> Result<(String, (String, String)), TokenManagerError> {
        let refresh = self.cryptographer.decrypt(&encrypted_refresh, &nonce)?;

        let refresh_token = self
            .redis_io
            .get(&format!("tokens:refresh:token:{}", &refresh.clone()))
            .await?;

        if refresh_token.is_empty() {
            return Err(TokenManagerError::NotFound(format!(
                "Refresh token {} not found",
                &refresh.clone()
            )));
        }

        self.redis_io
            .delete(&format!("tokens:refresh:token:{}", &refresh.clone()))
            .await?;

        let claims = self.access_validator.verify(&access, &public_pem)?;

        let access_token = self.access_provider.generate(&claims, &private_pem)?;
        let refresh_token = self.refresh_provider.generate();

        let refresh_to_exp_sec = 60 * 60 * 24 * 7;

        self.redis_io
            .setex(
                &format!("tokens:refresh:token:{}", &refresh_token),
                "exists",
                refresh_to_exp_sec,
            )
            .await?;

        let (encrypted_refresh, nonce) = self.cryptographer.encrypt(&refresh_token)?;

        Ok((access_token, (encrypted_refresh, nonce)))
    }
}
