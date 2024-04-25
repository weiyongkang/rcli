use std::path::PathBuf;

use clap::Parser;

use crate::process;

use super::{verify_path, CMDExector};

#[derive(Debug, Parser)]
pub enum HttpSubConnand {
    #[command(name = "server")]
    Server(HttpServerOpts),
}

#[derive(Debug, Parser)]
pub struct HttpServerOpts {
    #[arg(short,long,value_parser = verify_path ,default_value = ".")]
    pub dir: PathBuf,

    #[arg(short, long, default_value_t = 8080)]
    pub port: u16,
}

impl CMDExector for HttpServerOpts {
    async fn execute(self) -> anyhow::Result<()> {
        process::process_http_server(self.dir, self.port).await?;
        Ok(())
    }
}

impl CMDExector for HttpSubConnand {
    async fn execute(self) -> anyhow::Result<()> {
        match self {
            HttpSubConnand::Server(opts) => opts.execute().await,
        }
    }
}
