use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use thiserror::Error;
use tracing::error;

use crate::{
    domain::{models::claims::Claims, traits::token::jwt::token_provider::IJwtTokenProvider},
    infrastructure::token::jwks::claims::{JwksClaims, JwksClaimsError},
};

#[derive(Debug, Clone, Copy)]
pub struct JwksTokenProvider;

#[derive(Debug, Error)]
pub enum JwksTokenProviderError {
    #[error("Jwks claims error: {0}")]
    JwksClaims(#[from] JwksClaimsError),

    #[error("Rsa error: {0}")]
    Rsa(#[from] rsa::Error),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

impl IJwtTokenProvider for JwksTokenProvider {
    type Claims = Claims;
    type Error = JwksTokenProviderError;

    fn generate(
        &self,
        claims: &Claims,
        private_pem: &str,
    ) -> Result<String, JwksTokenProviderError> {
        let header = Header::new(Algorithm::RS256);

        let storage_claims =
            JwksClaims::from_domain_claims(&claims).map_err(|error| match error {
                _ => {
                    error!("{}", error);
                    error
                }
            })?;

        let key =
            EncodingKey::from_rsa_pem(private_pem.as_bytes()).map_err(|error| match error {
                _ => {
                    error!("{}", error);
                    error
                }
            })?;

        let token = encode(&header, &storage_claims, &key).map_err(|error| match error {
            _ => {
                error!("{}", error);
                error
            }
        })?;

        Ok(token)
    }
}
