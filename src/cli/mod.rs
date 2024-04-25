mod base64;
mod csv;
mod genpass;
mod http;
mod jwt;
mod text;
use clap::Parser;
use enum_dispatch::enum_dispatch;
use std::path::{Path, PathBuf};

pub use self::{base64::*, csv::*, genpass::*, http::*, jwt::*, text::*};
/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(name = "rcli",version, about, long_about = None)]
pub struct Opts {
    #[command(subcommand)]
    pub cmd: Subcommand,
}

#[derive(Parser, Debug)]
#[enum_dispatch(CMDExector)]
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
#[enum_dispatch]
pub trait CMDExector {
    async fn execute(self) -> anyhow::Result<()>;
}

impl CMDExector for Opts {
    async fn execute(self) -> anyhow::Result<()> {
        self.cmd.execute().await
    }
}
