use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use crate::domain::models::claims::Claims;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksClaims {
    pub sub: uuid::Uuid,
    pub jti: uuid::Uuid,
    pub iat: usize,
    pub exp: usize,
    //pub aud: String,
    //pub iss: Vec<String>,
    //pub role: String,
    //pub subscription: bool,
}

impl JwksClaims {
    pub fn from_domain_claims(value: &Claims) -> Result<Self, std::num::TryFromIntError> {
        let iat = datetime_to_usize(value.iat)?;
        let exp = datetime_to_usize(value.exp)?;

        Ok(Self {
            sub: value.sub,
            jti: value.jti,
            iat: iat,
            exp: exp
        })
    }
}

pub fn datetime_to_usize(datetime: DateTime<Utc>) -> Result<usize, std::num::TryFromIntError> {
    let timestamp = datetime.timestamp();

    let usize_timestamp = usize::try_from(timestamp)?;

    Ok(usize_timestamp)
}

pub fn usize_to_datetime(usize_timestamp: usize) -> DateTime<Utc> {
    let num_timestamp = usize_timestamp as i64;

    let datetime = Utc.timestamp_opt(num_timestamp, 0).unwrap();

    datetime
}
