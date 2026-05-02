use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use thiserror::Error;

use crate::{
    domain::{
        error::error_handling::log_err, models::claims::Claims,
        traits::token::jwt::token_validator::IJwtTokenValidator,
    },
    infrastructure::token::jwks::claims::{JwksClaims, JwksClaimsError, usize_to_datetime},
};

#[derive(Debug, Clone, Copy)]
pub struct JwksTokenValidator;

#[derive(Debug, Error)]
pub enum JwksTokenValidatorError {
    #[error("Rsa error: {0}")]
    Rsa(#[from] rsa::Error),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Jwks claims error: {0}")]
    JwksClaims(#[from] JwksClaimsError),
}

impl IJwtTokenValidator for JwksTokenValidator {
    type Claims = Claims;
    type Error = JwksTokenValidatorError;

    fn verify(&self, token: &str, public_pem: &str) -> Result<bool, Self::Error> {
        let key = DecodingKey::from_rsa_pem(public_pem.as_bytes()).map_err(log_err)?;

        let _ = decode::<JwksClaims>(&token, &key, &Validation::new(Algorithm::RS256))
            .map_err(log_err)?
            .claims;

        Ok(true)
    }

    fn decode(&self, token: &str, public_pem: &str) -> Result<Self::Claims, Self::Error> {
        let key = DecodingKey::from_rsa_pem(public_pem.as_bytes()).map_err(log_err)?;

        let storage_claims = decode::<JwksClaims>(&token, &key, &Validation::new(Algorithm::RS256))
            .map_err(log_err)?
            .claims;

        let claims = Claims {
            sub: storage_claims.sub,
            jti: storage_claims.jti,
            iat: usize_to_datetime(storage_claims.iat)?,
            exp: usize_to_datetime(storage_claims.exp)?,
        };

        Ok(claims)
    }
}
