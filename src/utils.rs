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
