use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::domain::{error::error_handling::log_err, models::claims::Claims};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksClaims {
    pub sub: uuid::Uuid,
    pub jti: uuid::Uuid,
    pub iat: usize,
    pub exp: usize,
}

#[derive(Debug, Error)]
pub enum JwksClaimsError {
    #[error("Try from int error: {0}")]
    TryFromInt(#[from] std::num::TryFromIntError),

    #[error("Datetime error: {0}")]
    Datetime(String),
}

impl JwksClaims {
    pub fn from_domain_claims(value: &Claims) -> Result<Self, JwksClaimsError> {
        let iat = datetime_to_usize(value.iat)?;
        let exp = datetime_to_usize(value.exp)?;

        Ok(Self {
            sub: value.sub,
            jti: value.jti,
            iat: iat,
            exp: exp,
        })
    }
}

pub fn datetime_to_usize(datetime: DateTime<Utc>) -> Result<usize, JwksClaimsError> {
    let timestamp = datetime.timestamp();

    let usize_timestamp = usize::try_from(timestamp).map_err(log_err)?;

    Ok(usize_timestamp)
}

pub fn usize_to_datetime(usize_timestamp: usize) -> Result<DateTime<Utc>, JwksClaimsError> {
    let num_timestamp = usize_timestamp as i64;

    let datetime = match Utc.timestamp_opt(num_timestamp, 0) {
        chrono::offset::LocalResult::Single(datetime) => Ok(datetime),
        chrono::offset::LocalResult::Ambiguous(_, _) => {
            Err(JwksClaimsError::Datetime("Ambigious datetime".to_string()))
        }
        chrono::offset::LocalResult::None => {
            Err(JwksClaimsError::Datetime("Unexpected time".to_string()))
        }
    }
    .map_err(log_err)?;

    Ok(datetime)
}
