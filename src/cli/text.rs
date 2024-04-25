use std::{fmt::Display, path::PathBuf, str::FromStr};

use clap::Parser;

use crate::{process, EncryptionKey};

use super::{verify_file, verify_path, CMDExector};

#[derive(Debug, Parser)]
pub enum TextSubConnand {
    #[command(name = "sign")]
    Sign(SignOpts),

    #[command(name = "verify")]
    Verify(VerifyOpts),

    #[command(name = "generate")]
    Generate(TextGenpassKeyOption),

    #[command(name = "encrypt")]
    Encrypt(EncryptOption),

    #[command(name = "decrypt")]
    Decrypt(DecryptOption),
}

#[derive(Debug, Parser)]
pub struct EncryptOption {
    #[arg(short,long,value_parser = verify_file,default_value = "-")]
    pub input: String,

    #[arg(short,long,value_parser = verify_file,default_value = "-")]
    pub key: String,
}

#[derive(Debug, Parser)]
pub struct DecryptOption {
    #[arg(short,long,value_parser = verify_file,default_value = "-")]
    pub input: String,

    #[arg(short,long,value_parser = verify_file,default_value = "-")]
    pub key: String,
}

#[derive(Debug, Parser)]
pub struct TextGenpassKeyOption {
    #[arg(short,long,value_parser = parse_format ,default_value = "blake3")]
    pub format: TextSignFormat,

    #[arg(short,long,value_parser = verify_path)]
    pub output: PathBuf,
}

#[derive(Debug, Parser)]
pub struct SignOpts {
    #[arg(short,long,value_parser = verify_file,default_value = "-")]
    pub input: String,

    #[arg(short,long,value_parser = verify_file,default_value = "-")]
    pub key: String,

    #[arg(short,long,value_parser = parse_format ,default_value = "blake3")]
    pub format: TextSignFormat,
}

#[derive(Debug, Parser)]
pub struct VerifyOpts {
    #[arg(short,long,value_parser = verify_file,default_value = "-")]
    pub input: String,

    #[arg(short,long,value_parser = verify_file,default_value = "-")]
    pub key: String,

    #[arg(short, long)]
    pub sign: String,

    #[arg(short,long,value_parser = parse_format ,default_value = "blake3")]
    pub format: TextSignFormat,
}

#[derive(Debug, Clone, Copy)]
pub enum TextSignFormat {
    Blake3,
    Ed25519,
}

fn parse_format(s: &str) -> Result<TextSignFormat, anyhow::Error> {
    s.parse()
}

impl FromStr for TextSignFormat {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "blake3" => Ok(TextSignFormat::Blake3),
            "ed25519" => Ok(TextSignFormat::Ed25519),
            e => anyhow::bail!("{} is format error", e),
        }
    }
}

impl From<TextSignFormat> for &str {
    fn from(value: TextSignFormat) -> Self {
        match value {
            TextSignFormat::Blake3 => "blake3",
            TextSignFormat::Ed25519 => "ed25519",
        }
    }
}

impl Display for TextSignFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // eprintln!("Display => 111");
        match *self {
            TextSignFormat::Blake3 => write!(f, "blake3"),
            TextSignFormat::Ed25519 => write!(f, "ed25519"),
        }
    }
}

impl CMDExector for SignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let sign = process::process_text_sign(&self.input, &self.key, self.format)?;
        println!("{}", sign);
        Ok(())
    }
}

impl CMDExector for VerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let verify = process::process_text_verify(&self.input, &self.key, self.format, &self.sign)?;
        println!("{}", verify);
        Ok(())
    }
}

impl CMDExector for TextGenpassKeyOption {
    async fn execute(self) -> anyhow::Result<()> {
        let key = process::process_text_generate(self.format)?;
        match key {
            EncryptionKey::Symmetric(k) => {
                let name = format!("{}.txt", self.format);
                let name = self.output.join(name);
                std::fs::write(name, k)?;
            }
            EncryptionKey::Asymmetric(pk, sk) => {
                let name = self.output.join(format!("{}.{}", self.format, "pk"));
                std::fs::write(name, pk)?;
                let name = self.output.join(format!("{}.{}", self.format, "sk"));
                std::fs::write(name, sk)?;
            }
        }
        Ok(())
    }
}

impl CMDExector for EncryptOption {
    async fn execute(self) -> anyhow::Result<()> {
        let encrypt = process::process_text_encrypt(&self.input, &self.key)?;
        println!("{}", encrypt);
        Ok(())
    }
}

impl CMDExector for DecryptOption {
    async fn execute(self) -> anyhow::Result<()> {
        let decrypt = process::process_text_decrypt(&self.input, &self.key)?;
        println!("{}", decrypt);
        Ok(())
    }
}

impl CMDExector for TextSubConnand {
    async fn execute(self) -> anyhow::Result<()> {
        match self {
            TextSubConnand::Sign(opts) => opts.execute().await,
            TextSubConnand::Verify(opts) => opts.execute().await,
            TextSubConnand::Generate(opts) => opts.execute().await,
            TextSubConnand::Encrypt(opts) => opts.execute().await,
            TextSubConnand::Decrypt(opts) => opts.execute().await,
        }
    }
}
