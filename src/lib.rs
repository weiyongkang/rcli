mod cli;
mod process;
mod utils;

pub use cli::{
    Base64Format, Base64SubConnand, HttpServerOpts, HttpSubConnand, JwtSubConnand, Opts,
    OutputFormat, Subcommand, TextSignFormat, TextSubConnand,
};
pub use process::{
    process_csv, process_decode, process_encode, process_genpass, process_http_server,
    process_jwt_sign, process_jwt_verify, process_text_decrypt, process_text_encrypt,
    process_text_generate, process_text_sign, process_text_verify, EncryptionKey,
};

pub use utils::*;

#[allow(async_fn_in_trait)]
pub trait CMDExector {
    type Item;
    async fn execute(self) -> anyhow::Result<Self::Item>;
}
