use std::io::Read;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE},
    Engine as _,
};

use crate::{cli::Base64Format, get_reader};

pub fn process_encode(input: &str, format: Base64Format) -> anyhow::Result<String> {
    let mut reader = get_reader(input)?;

    let mut data = Vec::new();

    reader.read_to_end(&mut data)?;

    let encoded = match format {
        Base64Format::Standard => STANDARD.encode(&data),
        Base64Format::UrlSafe => URL_SAFE.encode(&data),
    };

    Ok(encoded)
}

pub fn process_decode(input: &str, format: Base64Format) -> anyhow::Result<String> {
    let mut reader = get_reader(input)?;

    let mut data = String::new();
    reader.read_to_string(&mut data)?;

    // 清理 空白数据
    let data = data.trim();

    let encoded = match format {
        Base64Format::Standard => STANDARD.decode(data)?,
        Base64Format::UrlSafe => URL_SAFE.decode(data)?,
    };

    let encoded = String::from_utf8(encoded)?;

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
