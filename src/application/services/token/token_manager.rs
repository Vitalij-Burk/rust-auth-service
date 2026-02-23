use thiserror::Error;

use crate::domain::{
    models::claims::Claims,
    traits::token::{
        jwt::{token_provider::IJwtTokenProvider, token_validator::IJwtTokenValidator},
        opaque::token_provider::IOpaqueTokenProvider,
    },
};

#[derive(Debug, Clone, Copy)]
pub struct TokenManager<AccessProvider, AccessValidator, RefreshProvider, Storage> {
    pub access_provider: AccessProvider,
    pub access_validator: AccessValidator,
    pub refresh_provider: RefreshProvider,
    pub storage: Storage,
}

#[derive(Debug, Error)]
pub enum TokenManagerError {
    #[error("Jwt error: {0}")]
    JwtError(#[from] Box<dyn std::error::Error>),

    #[error("Redis storage error: {0}")]
    RedisError(#[from] redis::RedisError),

    #[error("Not found: {0}")]
    NotFound(String),
}

impl<AccessProvider, AccessValidator, RefreshProvider, Storage>
    TokenManager<AccessProvider, AccessValidator, RefreshProvider, Storage>
where
    AccessProvider: IJwtTokenProvider<Claims = Claims, Error = Box<dyn std::error::Error>>,
    AccessValidator: IJwtTokenValidator<Claims = Claims, Error = Box<dyn std::error::Error>>,
    RefreshProvider: IOpaqueTokenProvider,
    Storage: redis::AsyncCommands + Send + Sync,
{
    pub fn new(
        access_provider: AccessProvider,
        access_validator: AccessValidator,
        refresh_provider: RefreshProvider,
        storage: Storage,
    ) -> Self {
        Self {
            access_provider,
            access_validator,
            refresh_provider,
            storage,
        }
    }

    pub async fn generate_pair(
        &mut self,
        claims: &Claims,
        pem: &str,
    ) -> Result<(String, String), TokenManagerError> {
        let access_token = self.access_provider.generate(&claims, &pem)?;
        let refresh_token = self.refresh_provider.generate();

        let access_to_exp_sec = (claims.exp - &claims.iat).num_seconds() as u64;
        let refresh_to_exp_sec = 60 * 60 * 24 * 7;

        {
            self.storage
                .set_ex::<std::string::String, &std::string::String, ()>(
                    format!("tokens:access:jti:{}", &claims.jti),
                    &access_token,
                    access_to_exp_sec,
                )
                .await?;
            self.storage
                .set_ex::<std::string::String, &std::string::String, ()>(
                    format!("tokens:refresh:token:{}", &refresh_token),
                    &refresh_token,
                    refresh_to_exp_sec,
                )
                .await?;
        }

        Ok((access_token, refresh_token))
    }

    pub async fn verify_access(
        &mut self,
        access: &str,
        pem: &str,
    ) -> Result<Claims, TokenManagerError> {
        let claims = self.access_validator.verify(access, pem)?;

        let access = self
            .storage
            .get::<String, String>(format!("tokens:access:jti:{}", &claims.jti))
            .await?;

        println!("{}", access);

        if access.is_empty() {
            return Err(TokenManagerError::NotFound(format!("Access token with jti {} not found", &claims.jti)));
        }

        Ok(claims)
    }

    pub async fn verify_refresh(&mut self, refresh: &str) -> Result<(), TokenManagerError> {
        let refresh = self
            .storage
            .get::<String, String>(format!("tokens:refresh:token:{}", &refresh))
            .await?;

        if refresh.is_empty() {
            return Err(TokenManagerError::NotFound(format!("Refresh token {} not found", &refresh)));
        }

        Ok(())
    }

    pub async fn revoke_access(
        &mut self,
        access: &str,
        pem: &str,
    ) -> Result<(), TokenManagerError> {
        let claims = self.access_validator.verify(access, pem)?;

        {
            self.storage
                .del::<String, ()>(format!("tokens:access:jti:{}", &claims.jti))
                .await?;
        }

        Ok(())
    }

    pub async fn revoke_refresh(&mut self, refresh: &str) -> Result<(), TokenManagerError> {
        {
            self.storage
                .del::<String, ()>(format!("tokens:refresh:token:{}", &refresh))
                .await?;
        }

        Ok(())
    }

    pub async fn refresh(
        &mut self,
        refresh: &str,
        access: &str,
        private_pem: &str,
        public_pem: &str
    ) -> Result<(String, String), TokenManagerError> {
        let refresh = self
            .storage
            .get::<String, String>(format!("tokens:refresh:token:{}", &refresh))
            .await?;

        if refresh.is_empty() {
            return Err(TokenManagerError::NotFound(format!("Refresh token {} not found", &refresh)));
        }

        {
            self.storage
                .del::<String, ()>(format!("tokens:refresh:token:{}", &refresh))
                .await?;
        }

        let claims = self.access_validator.verify(&access, &public_pem)?;

        let access_token = self.access_provider.generate(&claims, &private_pem)?;
        let refresh_token = self.refresh_provider.generate();

        let access_to_exp_sec = (claims.exp - &claims.iat).num_seconds() as u64;
        let refresh_to_exp_sec = 60 * 60 * 24 * 7;

        {
            self.storage
                .set_ex::<std::string::String, &std::string::String, ()>(
                    format!("tokens:access:jti:{}", claims.jti),
                    &access_token,
                    access_to_exp_sec,
                )
                .await?;
            self.storage
                .set_ex::<std::string::String, &std::string::String, ()>(
                    format!("tokens:refresh:token:{}", &refresh_token),
                    &refresh_token,
                    refresh_to_exp_sec,
                )
                .await?;
        }

        Ok((access_token, refresh_token))
    }
}
