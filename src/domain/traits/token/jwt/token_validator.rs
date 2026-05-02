pub trait IJwtTokenValidator {
    type Claims;
    type Error;

    fn verify(&self, token: &str, pem: &str) -> Result<bool, Self::Error>;

    fn decode(&self, token: &str, pem: &str) -> Result<Self::Claims, Self::Error>;
}
