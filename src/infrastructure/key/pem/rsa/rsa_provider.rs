use rand::rngs::OsRng;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
};
use tracing::error;

#[derive(Debug, Clone, Copy)]
pub struct RsaPemProvider;

impl RsaPemProvider {
    pub fn generate_pair(&self) -> Result<(String, String), rsa::Error> {
        let mut rng = OsRng;

        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let private_pem = private_key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|error| match error {
                _ => {
                    error!("{}", error);
                    error
                }
            })?
            .to_string();

        let public_key = RsaPublicKey::from(&private_key);
        let public_pem = public_key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|error| match error {
                _ => {
                    error!("{}", error);
                    error
                }
            })?
            .to_string();

        Ok((private_pem, public_pem))
    }

    pub fn generate_from(&self, private_pem: &str) -> Result<String, rsa::Error> {
        let private_key =
            RsaPrivateKey::from_pkcs1_pem(private_pem).map_err(|error| match error {
                _ => {
                    error!("{}", error);
                    error
                }
            })?;

        let public_key = RsaPublicKey::from(&private_key);
        let public_pem = public_key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|error| match error {
                _ => {
                    error!("{}", error);
                    error
                }
            })?
            .to_string();

        Ok(public_pem)
    }

    pub fn generate_private(&self) -> Result<String, rsa::Error> {
        let mut rng = OsRng;

        let private_key = RsaPrivateKey::new(&mut rng, 2048).map_err(|error| match error {
            _ => {
                error!("{}", error);
                error
            }
        })?;
        let private_pem = private_key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|error| match error {
                _ => {
                    error!("{}", error);
                    error
                }
            })?
            .to_string();

        Ok(private_pem)
    }
}
