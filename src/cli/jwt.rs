use super::{verify_file, CMDExector};
use crate::{verify_time, JwtClaims};
use clap::Parser;

#[derive(Debug, Parser)]
pub enum JwtSubConnand {
    #[command(name = "sign")]
    Sign(JwtSignOpts),

    #[command(name = "verify")]
    Verify(JwtVerifyOpts),
}

#[derive(Debug, Parser)]
pub struct JwtVerifyOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub token: String,
    #[arg(short, long)]
    pub key: String,
}

#[derive(Debug, Parser)]
pub struct JwtSignOpts {
    #[arg(short, long)]
    pub aud: String,
    #[arg(short,long,value_parser = verify_time )]
    pub exp: usize,
    #[arg(short, long)]
    pub sub: String,
    #[arg(short, long)]
    pub iss: Option<String>,
    #[arg(short, long)]
    pub key: String,
}

impl CMDExector for JwtVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let is = match crate::process_jwt_verify(&self.token, &self.key) {
            Ok(is) => is,
            _ => false,
        };
        println!("{:?}", is);
        Ok(())
    }
}

impl CMDExector for JwtSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let claims: JwtClaims = self.into();
        println!("{:?}", claims);
        Ok(())
    }
}

impl CMDExector for JwtSubConnand {
    async fn execute(self) -> anyhow::Result<()> {
        match self {
            JwtSubConnand::Sign(opts) => opts.execute().await,
            JwtSubConnand::Verify(opts) => opts.execute().await,
        }
    }
}
