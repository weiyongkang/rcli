use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE},
    Engine as _,
};

use crate::{cli::Base64Format, IoF};

pub fn process_encode(input: &str, format: Base64Format) -> anyhow::Result<String> {
    let iof = IoF::new(input);
    let data = iof.read()?;

    let encoded = match format {
        Base64Format::Standard => STANDARD.encode(&data),
        Base64Format::UrlSafe => URL_SAFE.encode(&data),
    };

    Ok(encoded)
}

pub fn process_decode(input: &str, format: Base64Format) -> anyhow::Result<String> {
    let iof = IoF::new(input);
    let data = iof.read_to_string()?;

    let decoded = match format {
        Base64Format::Standard => STANDARD.decode(data)?,
        Base64Format::UrlSafe => URL_SAFE.decode(data)?,
    };

    let encoded = String::from_utf8(decoded)?;

    Ok(encoded)
}

#[cfg(test)]
mod test_base64 {

    use crate::{cli::Base64Format, process_decode, process_encode};

    #[test]
    fn test_encode() {
        let file = "Cargo.toml";
        let format = Base64Format::Standard;
        let _ = process_encode(file, format);
    }

    #[test]

    fn test_decode() {
        let encode = "assets\\base64.txt";
        let format = Base64Format::Standard;
        let _ = process_decode(encode, format);
    }
}
