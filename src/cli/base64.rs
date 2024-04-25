use std::{fmt::Display, str::FromStr};

use clap::{arg, Parser};

use crate::process;

use super::{verify_file, CMDExector};

#[derive(Debug, Parser)]
pub enum Base64SubConnand {
    #[command(name = "encode")]
    Encode(EncodeOpts),

    #[command(name = "decode")]
    Decode(DecodeOpts),
}

#[derive(Debug, Parser)]
pub struct EncodeOpts {
    #[arg(short,long,value_parser = verify_file,default_value = "-")]
    pub input: String,

    #[arg(long,value_parser = parse_base64_format ,default_value = "standard")]
    pub format: Base64Format,
}

#[derive(Debug, Parser)]
pub struct DecodeOpts {
    #[arg(short,long,value_parser = verify_file,default_value = "-")]
    pub input: String,

    #[arg(long,value_parser = parse_base64_format ,default_value = "standard")]
    pub format: Base64Format,
}

#[derive(Debug, Parser, Clone, Copy)]
pub enum Base64Format {
    Standard,
    UrlSafe,
}

fn parse_base64_format(s: &str) -> Result<Base64Format, anyhow::Error> {
    s.parse()
}

impl FromStr for Base64Format {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "standard" => Ok(Base64Format::Standard),
            "urlsafe" => Ok(Base64Format::UrlSafe),
            e => anyhow::bail!("{} is format error", e),
        }
    }
}

impl Display for Base64Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Base64Format::Standard => write!(f, "standard"),
            Base64Format::UrlSafe => write!(f, "urlsafe"),
        }
    }
}

impl CMDExector for EncodeOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let encode = process::process_encode(&self.input, self.format)?;
        println!("{}", encode);
        Ok(())
    }
}

impl CMDExector for DecodeOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let decode = process::process_decode(&self.input, self.format)?;
        println!("{}", decode);
        Ok(())
    }
}

impl CMDExector for Base64SubConnand {
    async fn execute(self) -> anyhow::Result<()> {
        match self {
            Self::Encode(opts) => opts.execute().await,
            Self::Decode(opts) => opts.execute().await,
        }
    }
}
