use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use crate::{get_reader, process_genpass, IoF, TextSignFormat};
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
        // let mut buf: Vec<u8> = Vec::new();
        // data.read_to_end(&mut buf)?;
        // Self::decrypt(&self, buf)

        //
        let mut strs = String::new();
        data.read_to_string(&mut strs)?;
        Self::decrypt(self, strs.trim().into())
    }
}

struct Chacha20 {
    pub key: [u8; 32],
}

impl Chacha20 {
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
        // let mut buf: Vec<u8> = Vec::new();
        // let _ = data.read_to_end(&mut buf)?;

        let key = chacha20poly1305::Key::clone_from_slice(self.key.as_slice());
        // let key = match key {
        //     Some(ok) => {
        //         ok
        //     },
        //     None => {
        //         anyhow::bail!("key is from error!")
        //     }
        // };

        // let mut ciphers = chacha20poly1305::ChaChaPoly1305::new_from_slice(self.key.as_slice());

        let mut ciphers = ChaCha20Poly1305::new(&key);
        let nonce: GenericArray<_, U12> =
            chacha20poly1305::Nonce::clone_from_slice(&self.key.as_slice()[0..12]);
        // let nonce:GenericArray<_,U12> = chacha20poly1305::ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message

        match ciphers.encrypt(&nonce, data.as_ref()) {
            core::result::Result::Ok(d) => Ok(URL_SAFE_NO_PAD.encode(d).into()),
            core::result::Result::Err(_) => {
                anyhow::bail!("data is from encrypt!")
            }
        }
    }
}

impl TextDecrypt for Chacha20 {
    fn decrypt(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        // let mut buf: Vec<u8> = Vec::new();
        // let _ = data.read_to_end(&mut buf)?;

        let data = URL_SAFE_NO_PAD.decode(data)?;

        let key = chacha20poly1305::Key::clone_from_slice(self.key.as_slice());
        // let key = match key {
        //     Some(ok) => {
        //         ok
        //     },
        //     None => {
        //         anyhow::bail!("key is from error!")
        //     }
        // };

        // let mut ciphers = chacha20poly1305::ChaChaPoly1305::new_from_slice(self.key.as_slice());

        let mut ciphers = ChaCha20Poly1305::new(&key);
        let nonce: GenericArray<_, U12> =
            chacha20poly1305::Nonce::clone_from_slice(&self.key.as_slice()[0..12]);

        match ciphers.decrypt(&nonce, data.as_ref()) {
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
