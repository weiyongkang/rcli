mod base64;
mod csv;
mod genpass;
mod http;
mod jwt;
mod text;
use std::path::{Path, PathBuf};

// use crate::CMDExector;

use self::{csv::CsvOption, genpass::GenpassOption};
use clap::Parser;

pub use self::base64::{Base64Format, Base64SubConnand};
pub use self::csv::OutputFormat;
pub use self::http::{HttpServerOpts, HttpSubConnand};
pub use self::jwt::JwtSubConnand;
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
    #[command(name = "csv")]
    Csv(CsvOption),
    #[command(name = "genpass")]
    Genpass(GenpassOption),
    #[command(subcommand)]
    Base64(Base64SubConnand),
    #[command(subcommand)]
    Text(TextSubConnand),
    #[command(subcommand)]
    Http(HttpSubConnand),
    #[command(subcommand)]
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
