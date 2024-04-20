use std::{fs, io::Read, path::Path};

use crate::{get_reader, process_genpass, TextSignFormat};
use anyhow::{Ok, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

pub fn process_text_sign(input: &str, key: &str, format: TextSignFormat) -> anyhow::Result<String> {
    let mut reader = get_reader(input)?;
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;

    let signed = match format {
        TextSignFormat::Blake3 => {
            let signer = Blake3::load(key)?;
            signer.sign(&mut reader)?
        }
        TextSignFormat::Ed25519 => {
            let signer = Ed25519Signer::load(key)?;
            signer.sign(&mut reader)?
        }
    };

    let data = URL_SAFE_NO_PAD.encode(signed);
    Ok(data)
}

pub fn process_text_verify(
    input: &str,
    key: &str,
    format: TextSignFormat,
    sign: &str,
) -> anyhow::Result<bool> {
    let mut reader = get_reader(input)?;
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;

    let sign = URL_SAFE_NO_PAD.decode(sign)?;

    let signed = match format {
        TextSignFormat::Blake3 => {
            let signer = Blake3::load(key)?;
            signer.verify(&mut reader, &sign)?
        }
        TextSignFormat::Ed25519 => {
            let signer = Ed25519Verify::load(key)?;
            signer.verify(&mut reader, &sign)?
        }
    };

    Ok(signed)
}

pub trait TextSign {
    fn sign(&self, data: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextVerify {
    fn verify(&self, data: impl Read, sig: &[u8]) -> Result<bool>;
}

pub struct Blake3 {
    key: [u8; 32],
}

impl Blake3 {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn try_new(key: &[u8]) -> Result<Self> {
        let key = &key[..32];
        let key = key.try_into().unwrap();
        let signer = Self::new(key);
        Ok(signer)
    }
}

impl TextSign for Blake3 {
    fn sign(&self, data: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf: Vec<u8> = Vec::new();
        let _ = data.read_to_end(&mut buf)?;
        Ok(blake3::keyed_hash(&self.key, &buf).as_bytes().to_vec())
    }
}

impl TextVerify for Blake3 {
    fn verify(&self, mut data: impl Read, sig: &[u8]) -> Result<bool> {
        let mut buf: Vec<u8> = Vec::new();
        let _ = data.read_to_end(&mut buf)?;
        let hash = blake3::keyed_hash(&self.key, &buf);
        let hash = hash.as_bytes();

        Ok(hash == sig)
    }
}

impl KeyLoader for Blake3 {
    fn load(path: impl AsRef<Path>) -> Result<Self>
    where
        Self: Sized,
    {
        let key: Vec<u8> = fs::read(path)?;
        Self::try_new(&key)
    }
}

pub struct Ed25519Signer {
    key: SigningKey,
}

impl TextSign for Ed25519Signer {
    fn sign(&self, data: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf: Vec<u8> = Vec::new();
        let _ = data.read_to_end(&mut buf)?;
        let sig = self.key.sign(&buf);
        Ok(sig.to_vec())
    }
}

impl Ed25519Signer {
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }

    pub fn try_new(key: &[u8]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(key.try_into()?);
        let signer = Self::new(signing_key);
        Ok(signer)
    }
}

pub struct Ed25519Verify {
    key: VerifyingKey,
}

impl TextVerify for Ed25519Verify {
    fn verify(&self, mut data: impl Read, sig: &[u8]) -> Result<bool> {
        let mut buf: Vec<u8> = Vec::new();
        let _ = data.read_to_end(&mut buf)?;
        let sig = Signature::from_bytes(&sig.try_into()?);
        if self.key.verify_strict(&buf, &sig).is_ok() {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl Ed25519Verify {
    pub fn new(key: VerifyingKey) -> Self {
        Self { key }
    }

    pub fn try_new(key: &[u8]) -> Result<Self> {
        let signing_key = VerifyingKey::from_bytes(key.try_into()?)?;
        let signer = Self::new(signing_key);
        Ok(signer)
    }
}

pub trait KeyLoader {
    fn load(path: impl AsRef<Path>) -> Result<Self>
    where
        Self: Sized;
}

impl KeyLoader for Ed25519Signer {
    fn load(path: impl AsRef<Path>) -> Result<Self>
    where
        Self: Sized,
    {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl KeyLoader for Ed25519Verify {
    fn load(path: impl AsRef<Path>) -> Result<Self>
    where
        Self: Sized,
    {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

pub trait KeyGenerator {
    fn generatr() -> Result<Encryption>;
}

impl KeyGenerator for Blake3 {
    fn generatr() -> Result<Encryption> {
        let key = process_genpass(32, true, true, true, false)?;
        let key = key.as_bytes().to_vec();
        Ok(Encryption::Symmetric(key))
    }
}

impl KeyGenerator for Ed25519Signer {
    fn generatr() -> Result<Encryption> {
        let mut csprng = OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let sk = sk.as_bytes().to_vec();
        Ok(Encryption::Asymmetric(pk, sk))
    }
}

pub fn process_text_generate(format: TextSignFormat) -> Result<Encryption> {
    match format {
        TextSignFormat::Blake3 => Blake3::generatr(),
        TextSignFormat::Ed25519 => Ed25519Signer::generatr(),
    }
}

#[derive(Debug, Clone)]
pub enum Encryption {
    Symmetric(Vec<u8>),           // 密钥
    Asymmetric(Vec<u8>, Vec<u8>), // 公钥和密钥
}

#[test]
fn test_generate() {
    let key = Blake3::generatr().unwrap();
    println!("{:?}", key);
    let key = Ed25519Signer::generatr().unwrap();
    println!("{:?}", key)
}
