use super::verify_file;
use crate::verify_time;
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
