use rand::rngs::OsRng;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
};

#[derive(Debug, Clone, Copy)]
pub struct RsaPemProvider;

impl RsaPemProvider {
    pub fn generate_pair(&self) -> (String, String) {
        let mut rng = OsRng;

        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let private_pem = private_key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string();

        let public_key = RsaPublicKey::from(&private_key);
        let public_pem = public_key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string();

        (private_pem, public_pem)
    }

    pub fn generate_from(&self, private_pem: &str) -> String {
        let private_key = RsaPrivateKey::from_pkcs1_pem(private_pem).unwrap();

        let public_key = RsaPublicKey::from(&private_key);
        let public_pem = public_key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string();

        public_pem
    }

    pub fn generate_private(&self) -> String {
        let mut rng = OsRng;

        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let private_pem = private_key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string();

        private_pem
    }
}
