use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

use crate::{domain::{
    models::claims::Claims, traits::token::jwt::token_provider::IJwtTokenProvider,
}, infrastructure::token::jwks::claims::JwksClaims};

#[derive(Debug, Clone, Copy)]
pub struct JwksTokenProvider;

impl IJwtTokenProvider for JwksTokenProvider {
    type Claims = Claims;
    type Error = Box<dyn std::error::Error>;

    fn generate(
        &self,
        claims: &Claims,
        private_pem: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let header = Header::new(Algorithm::RS256);

        let storage_claims = JwksClaims::from_domain_claims(&claims)?;

        let key = EncodingKey::from_rsa_pem(private_pem.as_bytes())?;

        let token = encode(&header, &storage_claims, &key)?;

        Ok(token)
    }
}
