use clap::Parser;
use std::path::Path;

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
}

#[derive(Parser, Debug)]
pub struct CsvOption {
    #[arg(long, short, value_parser = verify_input_file)]
    pub input: String,

    #[arg(long, short, default_value = "output.json")]
    pub output: String,

    #[arg(long, short, default_value_t = ',')]
    pub delimiter: char,

    #[arg(long, default_value_t = true)]
    pub header: bool,
}

fn verify_input_file(filename: &str) -> Result<String, String> {
    if Path::new(filename).exists() {
        Ok(filename.into())
    } else {
        Err("file is not exists".into())
    }
}
