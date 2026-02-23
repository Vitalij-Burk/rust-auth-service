use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub jti: Uuid,
    pub iat: DateTime<Utc>,
    pub exp: DateTime<Utc>,
    //pub aud: String,
    //pub iss: Vec<String>,
    //pub role: String,
    //pub subscription: bool,
}

impl Claims {
    pub fn new(sub: Uuid, jti: Uuid, iat: DateTime<Utc>, exp: DateTime<Utc>) -> Self {
        Self { sub, jti, iat, exp }
    }
}
