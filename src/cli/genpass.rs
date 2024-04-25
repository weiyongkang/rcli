use crate::process;
use clap::Parser;
use zxcvbn::zxcvbn;

use super::CMDExector;

#[derive(Parser, Debug)]
pub struct GenpassOption {
    #[arg(long, short, default_value_t = 16)]
    pub length: u8,

    #[arg(long, default_value_t = false)]
    pub no_uppercase: bool,

    #[arg(long, default_value_t = false)]
    pub no_lowercase: bool,

    #[arg(long, default_value_t = false)]
    pub no_number: bool,

    #[arg(long, default_value_t = false)]
    pub no_symbol: bool,
}

impl CMDExector for GenpassOption {
    async fn execute(self) -> anyhow::Result<()> {
        let pass = process::process_genpass(
            self.length,
            !self.no_uppercase,
            !self.no_lowercase,
            !self.no_number,
            !self.no_symbol,
        )?;
        println!("{}", pass);
        let estimate = zxcvbn(&pass, &[])?;
        eprintln!("password strength: {}", estimate.score());
        Ok(())
    }
}
