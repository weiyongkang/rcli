use std::fs::{self, File};
use std::io::{Read, Stdin};
use std::path::PathBuf;

use tracing::info;

pub fn get_reader(input: &str) -> anyhow::Result<Box<dyn Read>> {
    let reader: Box<dyn std::io::Read> = if input == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(File::open(input)?)
    };
    Ok(reader)
}

// 从输入流读取一行和读取文件
pub enum IoF {
    Stdin(Stdin),
    File(File),
}

impl IoF {
    pub fn read(&self) -> anyhow::Result<Vec<u8>> {
        let mut data = Vec::new();
        match self {
            Self::File(f) => {
                #[allow(clippy::borrow_deref_ref)]
                (&*f).read_to_end(&mut data)?;
            }
            Self::Stdin(input) => {
                let mut buf = String::new();
                input.read_line(&mut buf)?;
                data.extend_from_slice(buf.trim().as_bytes());
            }
        };
        Ok(data)
    }

    pub fn to_read(self) -> Box<dyn Read> {
        match self {
            Self::File(f) => Box::new(f),
            Self::Stdin(input) => Box::new(input),
        }
    }

    pub fn read_to_string(&self) -> anyhow::Result<String> {
        let mut data = String::new();
        match self {
            Self::File(f) => {
                #[allow(clippy::borrow_deref_ref)]
                (&*f).read_to_string(&mut data)?;
            }
            Self::Stdin(input) => {
                let mut buf = String::new();
                input.read_line(&mut buf)?;
                data.push_str(buf.trim());
            }
        };
        Ok(data)
    }

    pub fn new(input: &str) -> Self {
        if input == "-" {
            Self::Stdin(std::io::stdin())
        } else {
            let path = PathBuf::from(input);
            if !path.exists() || !path.is_file() {
                info!("file {} is not exists or is not file", input);
                Self::Stdin(std::io::stdin())
            } else {
                match fs::File::open(path) {
                    Ok(o) => Self::File(o),
                    _ => {
                        info!("file {} open error", input);
                        Self::Stdin(std::io::stdin())
                    }
                }
            }
        }
    }
}

pub fn verify_time(date: &str) -> anyhow::Result<usize> {
    let r = regex::Regex::new(r"^[0-9]{1,}[smhd]$").unwrap();
    if r.captures(date).is_none() {
        anyhow::bail!("{} is not format !!", date)
    } else {
        let (num_str, unit_str) = date.split_at(date.len() - 1);
        let val_unit: char = unit_str.chars().last().unwrap().to_ascii_lowercase();
        let val_number: usize = num_str.parse::<usize>().unwrap();

        match val_unit {
            's' => Ok(val_number),
            'm' => Ok(60 * val_number),
            'h' => Ok(60 * 60 * val_number),
            'd' => Ok(60 * 60 * 24 * val_number),
            v => anyhow::bail!("{} is not unit", v),
        }
    }
}
