mod base64;
mod csv;
mod genpass;
mod http;
mod jwt;
mod text;
use clap::Parser;
use std::path::{Path, PathBuf};

// use crate::CMDExector;

use self::{csv::CsvOption, genpass::GenpassOption};

pub use self::base64::{Base64Format, Base64SubConnand};
pub use self::csv::OutputFormat;
pub use self::http::{HttpServerOpts, HttpSubConnand};
pub use self::jwt::{JwtSignOpts, JwtSubConnand};
pub use self::text::{TextSignFormat, TextSubConnand};
/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(name = "rcli",version, about, long_about = None)]
pub struct Opts {
    #[command(subcommand)]
    pub cmd: Subcommand,
}

#[derive(Parser, Debug)]
pub enum Subcommand {
    #[command(name = "csv", about = "csv file operation")]
    Csv(CsvOption),
    #[command(name = "genpass", about = "generate password")]
    Genpass(GenpassOption),
    #[command(subcommand, about = "base64 encode/decode")]
    Base64(Base64SubConnand),
    #[command(subcommand, about = "text operation")]
    Text(TextSubConnand),
    #[command(subcommand, about = "http server")]
    Http(HttpSubConnand),
    #[command(subcommand, about = "jwt operation")]
    Jwt(JwtSubConnand),
}

fn verify_file(filename: &str) -> Result<String, String> {
    if filename == "-" || Path::new(filename).exists() {
        Ok(filename.into())
    } else {
        Err("file is not exists".into())
    }
}

fn verify_path(path: &str) -> Result<PathBuf, &'static str> {
    let p = Path::new(path);
    if p.exists() && p.is_dir() {
        Ok(PathBuf::from(path))
    } else {
        Err("is null or is file!")
    }
}

#[allow(async_fn_in_trait)]
pub trait CMDExector {
    async fn execute(self) -> anyhow::Result<()>;
}

impl CMDExector for Subcommand {
    async fn execute(self) -> anyhow::Result<()> {
        match self {
            Self::Csv(opts) => opts.execute().await,
            Self::Genpass(opts) => opts.execute().await,
            Self::Base64(opts) => opts.execute().await,
            Self::Text(opts) => opts.execute().await,
            Self::Http(opts) => opts.execute().await,
            Self::Jwt(opts) => opts.execute().await,
        }
    }
}

impl CMDExector for Opts {
    async fn execute(self) -> anyhow::Result<()> {
        self.cmd.execute().await
    }
}
