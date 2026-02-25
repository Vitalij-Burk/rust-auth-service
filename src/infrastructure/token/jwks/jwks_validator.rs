use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use tracing::error;

use crate::{
    domain::{models::claims::Claims, traits::token::jwt::token_validator::IJwtTokenValidator},
    infrastructure::token::jwks::claims::{JwksClaims, usize_to_datetime},
};

#[derive(Debug, Clone, Copy)]
pub struct JwksTokenValidator;

impl IJwtTokenValidator for JwksTokenValidator {
    type Claims = Claims;
    type Error = Box<dyn std::error::Error>;

    fn verify(&self, token: &str, public_pem: &str) -> Result<Claims, Box<dyn std::error::Error>> {
        let key =
            DecodingKey::from_rsa_pem(public_pem.as_bytes()).map_err(|error| match error {
                _ => {
                    error!("{}", error);
                    error
                }
            })?;

        let storage_claims = decode::<JwksClaims>(&token, &key, &Validation::new(Algorithm::RS256))
            .map_err(|error| match error {
                _ => {
                    error!("{}", error);
                    error
                }
            })?
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
