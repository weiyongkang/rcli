use std::fs;

use clap::Parser;
use rcli::{
    process_csv, process_decode, process_encode, process_genpass, process_text_generate,
    process_text_sign, process_text_verify, Base64SubConnand, Encryption, Opts, Subcommand,
    TextSubConnand,
};
use zxcvbn::zxcvbn;

fn main() -> anyhow::Result<()> {
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
                    Encryption::Symmetric(k) => {
                        let name = format!("{}.txt", opts.format);
                        let name = opts.output.join(name);
                        fs::write(name, k)?;
                    }
                    Encryption::Asymmetric(pk, sk) => {
                        let name = opts.output.join(format!("{}.{}", opts.format, "pk"));
                        fs::write(name, pk)?;
                        let name = opts.output.join(format!("{}.{}", opts.format, "sk"));
                        fs::write(name, sk)?;
                    }
                }
            }
        },
    }
    Ok(())
}
