use std::time::{Duration, SystemTime};

use clap::Parser;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::{cli::JwtSignOpts, IoF};

#[derive(Debug, Parser)]
pub struct JwtVerifyOpts {}

impl From<JwtSignOpts> for JwtClaims {
    fn from(value: JwtSignOpts) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as usize;
        let exp = Duration::from_secs(value.exp as u64);
        let exp = (SystemTime::now() + exp)
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as usize;
        let new = Self {
            aud: value.aud,
            exp,
            sub: value.sub,
            nbf: now,
            iss: value.iss,
        };

        println!(
            "{:?} => {:?}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
            now
        );
        println!("self: {:?}", new);
        new
    }
}

impl JwtClaims {
    #[allow(dead_code)]
    pub fn sign(&self, key: &str) -> anyhow::Result<String> {
        let token = encode(
            &Header::default(),
            &self,
            &EncodingKey::from_secret(key.as_bytes()),
        )?;
        Ok(token)
    }

    #[allow(dead_code)]
    pub fn new(aud: String, exp: usize, sub: String, iss: Option<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as usize;
        let exp = Duration::from_secs(exp as u64);
        let exp = (SystemTime::now() + exp)
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as usize;
        Self {
            aud,
            exp,
            sub,
            nbf: now,
            iss,
        }
    }

    #[allow(dead_code)]
    pub fn from_sign(token: &str, key: &str) -> anyhow::Result<Self> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_aud = false;
        let val = decode::<JwtClaims>(token, &DecodingKey::from_secret(key.as_ref()), &validation)?;
        Ok(val.claims)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JwtClaims {
    aud: String,
    exp: usize,
    sub: String,
    nbf: usize,
    iss: Option<String>,
}

//==============================================================================

pub fn process_jwt_sign(
    aud: String,
    exp: usize,
    sub: String,
    iss: Option<String>,
    key: String,
) -> anyhow::Result<String> {
    let claims = JwtClaims::new(aud, exp, sub, iss);
    let jwt = claims.sign(&key)?;
    Ok(jwt)
}

pub fn process_jwt_verify(token: &str, key: &str) -> anyhow::Result<bool> {
    let iof = IoF::new(token);
    let token: String = String::from_utf8(iof.read()?)?;
    match JwtClaims::from_sign(&token, key) {
        Ok(claims) => Ok(claims.exp
            > SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs() as usize),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_time;

    #[test]
    fn test_jwt_claims() -> anyhow::Result<()> {
        let exp = verify_time("10m")?;
        let claims = JwtClaims::new("test".to_string(), exp, "test".to_string(), None);

        let key = "chinadci".to_string();

        let jwt = claims.sign(&key)?;
        println!("{}", jwt);
        let claims = JwtClaims::from_sign(&jwt, &key)?;
        println!("{:?}", claims);

        Ok(())
    }
}
