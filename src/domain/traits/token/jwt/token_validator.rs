pub trait IJwtTokenValidator {
    type Claims: Send + Sync;
    type Error;

    fn verify(&self, token: &str, pem: &str) -> Result<Self::Claims, Self::Error>;
}
