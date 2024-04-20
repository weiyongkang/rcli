use anyhow::{Ok, Result};
use rand::seq::SliceRandom;

// 去除 O0 Il，避免歧义，可以参考base58
const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWSYZ";
const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwsyz";
const NUMBER: &[u8] = b"123456789";
const SYMBOL: &[u8] = b"!@#$%^&*._-+=";

pub fn process_genpass(
    length: u8,
    upper: bool,
    lower: bool,
    number: bool,
    symbol: bool,
) -> Result<String> {
    let mut rng = rand::thread_rng();
    let mut password: Vec<u8> = Vec::new();
    let mut chars = Vec::<u8>::new();

    // 去除 O0 Il，避免歧义
    if upper {
        chars.extend_from_slice(UPPER);
        password.push(
            *UPPER
                .choose(&mut rng)
                .expect("UPPER won't be empty in this context"),
        );
    }

    if lower {
        chars.extend_from_slice(LOWER);
        password.push(
            *LOWER
                .choose(&mut rng)
                .expect("LOWER won't be empty in this context"),
        );
    }

    if number {
        chars.extend_from_slice(NUMBER);
        password.push(
            *NUMBER
                .choose(&mut rng)
                .expect("NUMBER won't be empty in this context"),
        );
    }

    if symbol {
        chars.extend_from_slice(SYMBOL);
        password.push(
            *SYMBOL
                .choose(&mut rng)
                .expect("SYMBOL won't be empty in this context"),
        );
    }

    for _ in 0..(length - password.len() as u8) {
        let c = chars
            .choose(&mut rng)
            .expect("chars won't be empty in this context");
        password.push(*c);
    }

    // 打乱顺序
    password.shuffle(&mut rng);

    // todo: make sure the password has at lease on of each type
    let password = String::from_utf8(password)?;
    Ok(password)
}
