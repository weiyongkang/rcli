use clap::Parser;
use rcli::{CMDExector, Opts};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let opts = Opts::parse();
    opts.execute().await?;
    Ok(())
}
