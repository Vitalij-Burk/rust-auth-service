use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::models::claims::Claims;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ClaimsDTO {
    pub sub: Uuid,
}

impl From<&ClaimsDTO> for Claims {
    fn from(value: &ClaimsDTO) -> Self {
        let jti = Uuid::new_v4();
        let iat = Utc::now();
        let exp = iat + Duration::minutes(15);
        
        Self { sub: value.sub, jti: jti, iat: iat, exp: exp }
    }
}
