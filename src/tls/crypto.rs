use pkgcrypto::crypto::aes_aead::Aes128Ccm;
use pkgcrypto::crypto::aes_aead::Aes128Gcm;
use pkgcrypto::crypto::aes_aead::Aes256Gcm;
use pkgcrypto::crypto::chacha20_poly1305::ChaCha20Poly1305;
use pkgcrypto::crypto::ed25519::Ed25519Signer;
use pkgcrypto::crypto::ed25519::Ed25519Verifier;
use pkgcrypto::crypto::error::CryptoError;
use pkgcrypto::crypto::feature::Aead as AeadFeature;
use pkgcrypto::crypto::feature::DiffieHellman as DiffieHellmanFeature;
use pkgcrypto::crypto::feature::DigitalSignatureSigner as DigitalSignatureSignerFeature;
use pkgcrypto::crypto::feature::DigitalSignatureVerifier as DigitalSignatureVerifierFeature;
use pkgcrypto::crypto::feature::Hash as HashFeature;
use pkgcrypto::crypto::feature::Mac as MacFeature;
use pkgcrypto::crypto::hmac_sha2::HmacSha256;
use pkgcrypto::crypto::hmac_sha2::HmacSha384;
use pkgcrypto::crypto::sha2::Sha256;
use pkgcrypto::crypto::sha2::Sha384;
use pkgcrypto::crypto::x25519::X25519;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    Aes128Ccm,
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

pub enum Aead {
    Aes128Ccm(Aes128Ccm),
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl AeadAlgorithm {

    pub fn instance(&self, key: &[u8]) -> Result<Aead, CryptoError> {
        return Aead::new(*self, key);
    }

    pub fn key_len(&self) -> usize {
        return match self {
            Self::Aes128Ccm        => Aes128Ccm::KEY_LEN,
            Self::Aes128Gcm        => Aes128Gcm::KEY_LEN,
            Self::Aes256Gcm        => Aes256Gcm::KEY_LEN,
            Self::ChaCha20Poly1305 => ChaCha20Poly1305::KEY_LEN,
        };
    }

    pub fn nonce_len(&self) -> usize {
        return match self {
            Self::Aes128Ccm        => Aes128Ccm::MAX_NONCE_LEN,
            Self::Aes128Gcm        => Aes128Gcm::MAX_NONCE_LEN,
            Self::Aes256Gcm        => Aes256Gcm::MAX_NONCE_LEN,
            Self::ChaCha20Poly1305 => ChaCha20Poly1305::MAX_NONCE_LEN,
        };
    }

    pub fn tag_len(&self) -> usize {
        return match self {
            Self::Aes128Ccm        => Aes128Ccm::TAG_LEN,
            Self::Aes128Gcm        => Aes128Gcm::TAG_LEN,
            Self::Aes256Gcm        => Aes256Gcm::TAG_LEN,
            Self::ChaCha20Poly1305 => ChaCha20Poly1305::TAG_LEN,
        };
    }

}

impl Aead {

    pub fn new(algo: AeadAlgorithm, key: &[u8]) -> Result<Self, CryptoError> {
        return match algo {
            AeadAlgorithm::Aes128Ccm        => Ok(Self::Aes128Ccm(Aes128Ccm::new(key)?)),
            AeadAlgorithm::Aes128Gcm        => Ok(Self::Aes128Gcm(Aes128Gcm::new(key)?)),
            AeadAlgorithm::Aes256Gcm        => Ok(Self::Aes256Gcm(Aes256Gcm::new(key)?)),
            AeadAlgorithm::ChaCha20Poly1305 => Ok(Self::ChaCha20Poly1305(ChaCha20Poly1305::new(key)?)),
        };
    }

    pub fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Aes128Ccm(v)        => v.rekey(key).err(),
            Self::Aes128Gcm(v)        => v.rekey(key).err(),
            Self::Aes256Gcm(v)        => v.rekey(key).err(),
            Self::ChaCha20Poly1305(v) => v.rekey(key).err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn encrypt_and_generate(&mut self, nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Aes128Ccm(v)        => v.encrypt_and_generate(nonce, aad, plaintext, ciphertext, tag),
            Self::Aes128Gcm(v)        => v.encrypt_and_generate(nonce, aad, plaintext, ciphertext, tag),
            Self::Aes256Gcm(v)        => v.encrypt_and_generate(nonce, aad, plaintext, ciphertext, tag),
            Self::ChaCha20Poly1305(v) => v.encrypt_and_generate(nonce, aad, plaintext, ciphertext, tag),
        };
    }

    pub fn decrypt_and_verify(&mut self, nonce: &[u8], aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {
        return match self {
            Self::Aes128Ccm(v)        => v.decrypt_and_verify(nonce, aad, ciphertext, plaintext, tag),
            Self::Aes128Gcm(v)        => v.decrypt_and_verify(nonce, aad, ciphertext, plaintext, tag),
            Self::Aes256Gcm(v)        => v.decrypt_and_verify(nonce, aad, ciphertext, plaintext, tag),
            Self::ChaCha20Poly1305(v) => v.decrypt_and_verify(nonce, aad, ciphertext, plaintext, tag),
        };
    }

    pub fn encrypt_and_generate_overwrite(&mut self, nonce: &[u8], aad: &[u8], text: &mut [u8],
        tag: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Aes128Ccm(v)        => v.encrypt_and_generate_overwrite(nonce, aad, text, tag),
            Self::Aes128Gcm(v)        => v.encrypt_and_generate_overwrite(nonce, aad, text, tag),
            Self::Aes256Gcm(v)        => v.encrypt_and_generate_overwrite(nonce, aad, text, tag),
            Self::ChaCha20Poly1305(v) => v.encrypt_and_generate_overwrite(nonce, aad, text, tag),
        };
    }

    pub fn decrypt_and_verify_overwrite(&mut self, nonce: &[u8], aad: &[u8], text: &mut [u8],
        tag: &[u8]) -> Result<bool, CryptoError> {
        return match self {
            Self::Aes128Ccm(v)        => v.decrypt_and_verify_overwrite(nonce, aad, text, tag),
            Self::Aes128Gcm(v)        => v.decrypt_and_verify_overwrite(nonce, aad, text, tag),
            Self::Aes256Gcm(v)        => v.decrypt_and_verify_overwrite(nonce, aad, text, tag),
            Self::ChaCha20Poly1305(v) => v.decrypt_and_verify_overwrite(nonce, aad, text, tag),
        };
    }

}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DiffieHellmanAlgorithm {
    X25519,
}

pub enum DiffieHellman {
    X25519(X25519),
}

impl DiffieHellmanAlgorithm {

    pub fn priv_key_len(&self) -> usize {
        return match self {
            Self::X25519 => X25519::PRIVATE_KEY_LEN,
        };
    }

    pub fn pub_key_len(&self) -> usize {
        return match self {
            Self::X25519 => X25519::PUBLIC_KEY_LEN,
        };
    }

    pub fn shared_secret_len(&self) -> usize {
        return match self {
            Self::X25519 => X25519::SHARED_SECRET_LEN,
        };
    }

    pub fn compute_public_key_oneshot(&self, priv_key: &[u8], pub_key: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            DiffieHellmanAlgorithm::X25519 => X25519::compute_public_key_oneshot(priv_key, pub_key),
        };
    }

    pub fn compute_shared_secret_oneshot(&self, priv_key: &[u8], peer_pub_key: &[u8],
        shared_secret: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            DiffieHellmanAlgorithm::X25519 => X25519::compute_shared_secret_oneshot(priv_key,
                peer_pub_key, shared_secret),
        };
    }

}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DigitalSignatureAlgorithm {
    Ed25519,
}

pub enum DigitalSignatureSigner {
    Ed25519(Ed25519Signer),
}

pub enum DigitalSignatureVerifier {
    Ed25519(Ed25519Verifier),
}

impl DigitalSignatureAlgorithm {

    pub fn signer_instance(&self, priv_key: &[u8]) -> Result<DigitalSignatureSigner, CryptoError> {
        return DigitalSignatureSigner::new(*self, priv_key);
    }

    pub fn verifier_instance(&self, pub_key: &[u8]) -> Result<DigitalSignatureVerifier, CryptoError> {
        return DigitalSignatureVerifier::new(*self, pub_key);
    }

    pub fn priv_key_len(&self) -> usize {
        return match self {
            Self::Ed25519 => Ed25519Signer::PRIVATE_KEY_LEN,
        };
    }

    pub fn pub_key_len(&self) -> usize {
        return match self {
            Self::Ed25519 => Ed25519Signer::PUBLIC_KEY_LEN,
        };
    }

    pub fn signature_len(&self) -> usize {
        return match self {
            Self::Ed25519 => Ed25519Signer::SIGNATURE_LEN,
        };
    }

    pub fn compute_public_key_oneshot(&self, priv_key: &[u8], pub_key: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Ed25519 => Ed25519Signer::compute_public_key_oneshot(priv_key, pub_key),
        };
    }

    pub fn sign_oneshot(&self, priv_key: &[u8], msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Ed25519 => Ed25519Signer::sign_oneshot(priv_key, msg, signature),
        };
    }

    pub fn verify_oneshot(&self, pub_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        return match self {
            Self::Ed25519 => Ed25519Verifier::verify_oneshot(pub_key, msg, signature),
        };
    }

}

impl DigitalSignatureSigner {

    pub fn new(algo: DigitalSignatureAlgorithm, priv_key: &[u8]) -> Result<Self, CryptoError> {
        return match algo {
            DigitalSignatureAlgorithm::Ed25519 => Ok(Self::Ed25519(Ed25519Signer::new(priv_key)?)),
        };
    }

    pub fn rekey(&mut self, priv_key: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Ed25519(v) => v.rekey(priv_key).err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn compute_public_key(&self, pub_key: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Ed25519(v) => v.compute_public_key(pub_key),
        };
    }

    pub fn sign(&self, msg: &[u8], signature: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Ed25519(v) => v.sign(msg, signature),
        };
    }

}

impl DigitalSignatureVerifier {

    pub fn new(algo: DigitalSignatureAlgorithm, pub_key: &[u8]) -> Result<Self, CryptoError> {
        return match algo {
            DigitalSignatureAlgorithm::Ed25519 => Ok(Self::Ed25519(Ed25519Verifier::new(pub_key)?)),
        };
    }

    pub fn rekey(&mut self, pub_key: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Ed25519(v) => v.rekey(pub_key).err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        return match self {
            Self::Ed25519(v) => v.verify(msg, signature),
        };
    }

}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
}

pub enum Hash {
    Sha256(Sha256),
    Sha384(Sha384),
}

impl HashAlgorithm {

    pub fn instance(&self) -> Hash {
        return Hash::new(*self);
    }

    pub fn md_len(&self) -> usize {
        return match self {
            Self::Sha256 => Sha256::MESSAGE_DIGEST_LEN,
            Self::Sha384 => Sha384::MESSAGE_DIGEST_LEN,
        };
    }

    pub fn digest_oneshot(&self, msg: &[u8], md: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::Sha256 => Sha256::digest_oneshot(msg, md),
            Self::Sha384 => Sha384::digest_oneshot(msg, md),
        };
    }

}

impl Hash {

    pub fn new(algo: HashAlgorithm) -> Self {
        return match algo {
            HashAlgorithm::Sha256 => Self::Sha256(Sha256::new()),
            HashAlgorithm::Sha384 => Self::Sha384(Sha384::new()),
        };
    }

    pub fn reset(&mut self) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Sha256(v) => v.reset().err(),
            Self::Sha384(v) => v.reset().err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::Sha256(v) => v.update(msg).err(),
            Self::Sha384(v) => v.update(msg).err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn digest(&mut self, md: &mut [u8]) -> Result<(), CryptoError> {
        return if let Some(e) = match self {
            Self::Sha256(v) => v.digest(md).err(),
            Self::Sha384(v) => v.digest(md).err(),
        } { Err(e) } else { Ok(()) };
    }

}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HmacAlgorithm {
    HmacSha256,
    HmacSha384,
}

pub enum Hmac {
    HmacSha256(HmacSha256),
    HmacSha384(HmacSha384),
}

impl HmacAlgorithm {

    pub fn instance(&self, key: &[u8]) -> Result<Hmac, CryptoError> {
        return Hmac::new(*self, key);
    }

    pub fn mac_len(&self) -> usize {
        return match self {
            Self::HmacSha256 => HmacSha256::MAC_LEN,
            Self::HmacSha384 => HmacSha384::MAC_LEN,
        };
    }

    pub fn compute_oneshot(&self, key: &[u8], msg: &[u8], md: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::HmacSha256 => HmacSha256::compute_oneshot(key, msg, md),
            Self::HmacSha384 => HmacSha384::compute_oneshot(key, msg, md),
        };
    }

}

impl Hmac {

    pub fn new(algo: HmacAlgorithm, key: &[u8]) -> Result<Self, CryptoError> {
        return match algo {
            HmacAlgorithm::HmacSha256 => Ok(Self::HmacSha256(HmacSha256::new(key)?)),
            HmacAlgorithm::HmacSha384 => Ok(Self::HmacSha384(HmacSha384::new(key)?)),
        };
    }

    pub fn rekey(&mut self, key: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::HmacSha256(v) => v.rekey(key).err(),
            Self::HmacSha384(v) => v.rekey(key).err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn reset(&mut self) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::HmacSha256(v) => v.reset().err(),
            Self::HmacSha384(v) => v.reset().err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn update(&mut self, msg: &[u8]) -> Result<&mut Self, CryptoError> {
        return if let Some(e) = match self {
            Self::HmacSha256(v) => v.update(msg).err(),
            Self::HmacSha384(v) => v.update(msg).err(),
        } { Err(e) } else { Ok(self) };
    }

    pub fn compute(&mut self, mac: &mut [u8]) -> Result<(), CryptoError> {
        return match self {
            Self::HmacSha256(v) => v.compute(mac),
            Self::HmacSha384(v) => v.compute(mac),
        };
    }

}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {

    if a.len() != b.len() {
        return false;
    }

    let mut s: u8 = 0;

    for i in 0..a.len() {
        s = s | (a[i] ^ b[i]);
    }

    return s == 0;

}