pub trait IJwtTokenProvider {
    type Claims: Send + Sync;
    type Error;

    fn generate(&self, claims: &Self::Claims, pem: &str) -> Result<String, Self::Error>;
}
