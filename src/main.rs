use std::fs;

use clap::Parser;
use rcli::{
    process_csv, process_decode, process_encode, process_genpass, process_http_server,
    process_text_decrypt, process_text_encrypt, process_text_generate, process_text_sign,
    process_text_verify, Base64SubConnand, EncryptionKey, HttpSubConnand, Opts, Subcommand,
    TextSubConnand,
};
use zxcvbn::zxcvbn;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let opts = Opts::parse();
    match opts.cmd {
        Subcommand::Csv(opts) => {
            let output = if let Some(v) = opts.output {
                v.clone()
            } else {
                format!("output.{}", opts.format)
            };
            process_csv(&opts.input, &output, opts.format)?
        }
        Subcommand::Genpass(opts) => {
            let password = process_genpass(
                opts.length,
                !opts.no_uppercase,
                !opts.no_lowercase,
                !opts.no_number,
                !opts.no_symbol,
            )?;
            println!("password: {}", password);

            let estimate = zxcvbn(&password, &[])?;
            eprintln!("password strength: {}", estimate.score());
        }
        Subcommand::Base64(opts) => match opts {
            Base64SubConnand::Decode(opts) => {
                let v = process_decode(&opts.input, opts.format)?;
                println!("{}", v);
            }
            Base64SubConnand::Encode(opts) => {
                let v = process_encode(&opts.input, opts.format)?;
                println!("{}", v);
            }
        },
        Subcommand::Text(opts) => match opts {
            TextSubConnand::Sign(opts) => {
                let sign = process_text_sign(&opts.input, &opts.key, opts.format)?;
                println!("{}", sign);
            }
            TextSubConnand::Verify(opts) => {
                let verify = process_text_verify(&opts.input, &opts.key, opts.format, &opts.sign)?;
                println!("{}", verify);
            }
            TextSubConnand::Generate(opts) => {
                let key = process_text_generate(opts.format)?;
                match key {
                    EncryptionKey::Symmetric(k) => {
                        let name = format!("{}.txt", opts.format);
                        let name = opts.output.join(name);
                        fs::write(name, k)?;
                    }
                    EncryptionKey::Asymmetric(pk, sk) => {
                        let name = opts.output.join(format!("{}.{}", opts.format, "pk"));
                        fs::write(name, pk)?;
                        let name = opts.output.join(format!("{}.{}", opts.format, "sk"));
                        fs::write(name, sk)?;
                    }
                }
            }
            TextSubConnand::Decrypt(opts) => {
                let data = process_text_decrypt(&opts.input, &opts.key)?;
                println!("{}", data);
            }
            TextSubConnand::Encrypt(opts) => {
                let data = process_text_encrypt(&opts.input, &opts.key)?;
                println!("{}", data);
            }
        },
        Subcommand::Http(opts) => match opts {
            HttpSubConnand::Server(server) => {
                process_http_server(server.dir, server.port).await?;
            }
        },
        Subcommand::Jwt(opts) => {
            println!("{:?}", opts)
        }
    }
    Ok(())
}
