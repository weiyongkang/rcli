use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use crate::{process_genpass, IoF, TextSignFormat};
use anyhow::{Ok, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{generic_array::GenericArray, AeadMut},
    consts::U12,
    ChaCha20Poly1305, KeyInit,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

pub fn process_text_sign(input: &str, key: &str, format: TextSignFormat) -> anyhow::Result<String> {
    let iof = IoF::new(input);
    let mut data = iof.to_read();

    let signed = match format {
        TextSignFormat::Blake3 => {
            let signer = Blake3::load(key)?;
            signer.sign(&mut data)?
        }
        TextSignFormat::Ed25519 => {
            let signer = Ed25519Signer::load(key)?;
            signer.sign(&mut data)?
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
    let iof = IoF::new(input);
    let mut data = iof.to_read();

    let sign = URL_SAFE_NO_PAD.decode(sign)?;

    let signed = match format {
        TextSignFormat::Blake3 => {
            let signer = Blake3::load(key)?;
            signer.verify(&mut data, &sign)?
        }
        TextSignFormat::Ed25519 => {
            let signer = Ed25519Verify::load(key)?;
            signer.verify(&mut data, &sign)?
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
    #[allow(dead_code)]
    salt: [u8; 32],
}

impl Blake3 {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key, salt: key }
    }

    pub fn try_new(key: &[u8]) -> Result<Self> {
        let key = &key[..32];
        let key = key.try_into().unwrap();
        let this = Self::new(key);
        Ok(this)
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
    fn generatr() -> Result<EncryptionKey>;
}

impl KeyGenerator for Blake3 {
    fn generatr() -> Result<EncryptionKey> {
        let key = process_genpass(32, true, true, true, false)?;
        let key = key.as_bytes().to_vec();
        Ok(EncryptionKey::Symmetric(key))
    }
}

impl KeyGenerator for Ed25519Signer {
    fn generatr() -> Result<EncryptionKey> {
        let mut csprng = OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let sk = sk.as_bytes().to_vec();
        Ok(EncryptionKey::Asymmetric(pk, sk))
    }
}

pub fn process_text_generate(format: TextSignFormat) -> Result<EncryptionKey> {
    match format {
        TextSignFormat::Blake3 => Blake3::generatr(),
        TextSignFormat::Ed25519 => Ed25519Signer::generatr(),
    }
}

#[derive(Debug, Clone)]
pub enum EncryptionKey {
    Symmetric(Vec<u8>),           // 密钥
    Asymmetric(Vec<u8>, Vec<u8>), // 公钥和密钥
}

//=============================================================================================

pub trait TextEncrypt {
    fn encrypt(&self, data: Vec<u8>) -> Result<Vec<u8>>;

    fn encrypt_in_read(&self, mut data: impl Read) -> Result<Vec<u8>> {
        // let mut buf: Vec<u8> = Vec::new();
        // data.read_to_end(&mut buf)?;
        // Self::encrypt(&self, buf)

        let mut strs = String::new();
        data.read_to_string(&mut strs)?;
        Self::encrypt(self, strs.trim().into())
    }
}

pub trait TextDecrypt {
    fn decrypt(&self, data: Vec<u8>) -> Result<Vec<u8>>;

    fn decrypt_in_read(&self, mut data: impl Read) -> Result<Vec<u8>> {
        let mut strs = String::new();
        data.read_to_string(&mut strs)?;
        Self::decrypt(self, strs.trim().into())
    }
}

struct Chacha20 {
    pub key: [u8; 32],
    // pub salt: [u8; 12],
}

impl Chacha20 {
    pub fn new(key: [u8; 32]) -> Self {
        // let salt: GenericArray<_, U12> = chacha20poly1305::ChaCha20Poly1305::generate_nonce(&mut OsRng);
        Self { key }
    }

    pub fn try_new(key: &[u8]) -> Result<Self> {
        let key = &key[..32];
        let key = key.try_into().unwrap();
        let signer = Self::new(key);
        Ok(signer)
    }
}

impl KeyLoader for Chacha20 {
    fn load(path: impl AsRef<Path>) -> Result<Self>
    where
        Self: Sized,
    {
        let key: Vec<u8> = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl TextEncrypt for Chacha20 {
    fn encrypt(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        let key = chacha20poly1305::Key::clone_from_slice(self.key.as_slice());
        let mut ciphers = ChaCha20Poly1305::new(&key);
        let salt = process_genpass(12, true, true, true, false)?; // 生成 12 位随机数
        let nonce: GenericArray<_, U12> =
            chacha20poly1305::Nonce::clone_from_slice(salt.as_bytes());
        match ciphers.encrypt(&nonce, data.as_slice()) {
            core::result::Result::Ok(d) => {
                let value: String = URL_SAFE_NO_PAD.encode(d);
                let salt: String = URL_SAFE_NO_PAD.encode(salt);
                Ok(format!("{}|{}", value, salt).as_bytes().to_vec())
            }
            core::result::Result::Err(_) => {
                anyhow::bail!("data is from encrypt!")
            }
        }
    }
}

impl TextDecrypt for Chacha20 {
    fn decrypt(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        let data = String::from_utf8(data)?;
        let sp = data.split_terminator('|').collect::<Vec<&str>>(); // 通过 | 分割

        let data = URL_SAFE_NO_PAD.decode(sp[0])?;
        let nonce = URL_SAFE_NO_PAD.decode(sp[1])?;

        let key: GenericArray<u8, _> = chacha20poly1305::Key::clone_from_slice(self.key.as_slice());

        let mut ciphers = ChaCha20Poly1305::new(&key);
        let nonce: GenericArray<_, U12> =
            chacha20poly1305::Nonce::clone_from_slice(nonce.as_slice());

        match ciphers.decrypt(&nonce, data.as_slice()) {
            core::result::Result::Ok(d) => Ok(d),
            core::result::Result::Err(_) => {
                anyhow::bail!("data is from encrypt!")
            }
        }
    }
}

pub fn process_text_encrypt(input: &str, key: &str) -> Result<String> {
    let iof = IoF::new(input);
    let encrypt = Chacha20::load(PathBuf::from(key))?;
    let ret = encrypt.encrypt(iof.read()?)?;
    Ok(String::from_utf8(ret)?)
}

pub fn process_text_decrypt(input: &str, key: &str) -> Result<String> {
    let iof = IoF::new(input);
    let encrypt: Chacha20 = Chacha20::load(PathBuf::from(key))?;
    let ret = encrypt.decrypt(iof.read()?)?;
    Ok(String::from_utf8(ret)?)
}

#[test]
fn test_chacha20play() -> Result<()> {
    let chacha20 = Chacha20 { key: [8u8; 32] };

    let strs = "sdasdsadad";
    let content = strs.as_bytes().to_vec();

    let encrypt = chacha20.encrypt(content)?;
    let decrypt = chacha20.decrypt(encrypt)?;

    println!("{},{}", strs, String::from_utf8(decrypt)?);

    Ok(())
}
