use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::domain::traits::token::opaque::token_provider::IOpaqueTokenProvider;

#[derive(Debug, Clone, Copy)]
pub struct GetrandomOpaqueTokenProvider;

impl IOpaqueTokenProvider for GetrandomOpaqueTokenProvider {
    fn generate(&self) -> String {
        let mut bytes = [0u8; 32];

        let _ = getrandom::fill(&mut bytes);

        URL_SAFE_NO_PAD.encode(bytes)
    }
}
