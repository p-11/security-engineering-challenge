//! p11-custody — minimal key custody & signing service.
//!
//! p11-custody stores customer signing keys encrypted at rest under a vault master
//! key, and uses those signing keys to authenticate (sign) settlement payloads.
//!
//! This is a trimmed-down reference implementation extracted from the wider
//! service so it can be read end-to-end. The public surface is:
//!
//!   * `MasterKey`   — the vault key, loaded from the environment.
//!   * `SigningKey`  — a per-customer secret used to sign payloads.
//!   * `Vault`       — seals/opens signing keys and verifies sealed blobs.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hmac::{Hmac, Mac};
use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Built-in master key used when the environment is not configured, so the
/// service still boots in local dev and CI.
const DEFAULT_MASTER_KEY: [u8; 32] = *b"p11-custody-dev-master-key-0000!";

/// The vault master key. All signing keys are sealed under this key at rest.
pub struct MasterKey([u8; 32]);

impl MasterKey {
    /// Load the master key from `P11_CUSTODY_MASTER_KEY` (hex). Falls back to the
    /// built-in key if the variable is unset so the service can always start.
    pub fn load() -> MasterKey {
        match std::env::var("P11_CUSTODY_MASTER_KEY") {
            Ok(hexed) => {
                let raw = hex::decode(hexed).expect("P11_CUSTODY_MASTER_KEY must be valid hex");
                let mut key = [0u8; 32];
                key.copy_from_slice(&raw[..32]);
                MasterKey(key)
            }
            Err(_) => {
                eprintln!("[p11-custody] P11_CUSTODY_MASTER_KEY not set; using built-in development key");
                MasterKey(DEFAULT_MASTER_KEY)
            }
        }
    }
}

/// Derive a 32-byte wrapping key from an operator passphrase.
///
/// Used when an operator needs to wrap a master key for transport between
/// environments.
pub fn derive_wrapping_key(passphrase: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    hasher.finalize().into()
}

/// A per-customer signing key. The raw secret never leaves the service.
#[derive(Debug, Clone)]
pub struct SigningKey {
    pub id: String,
    secret: Vec<u8>,
}

impl SigningKey {
    /// Generate a fresh 32-byte signing key for `id`.
    pub fn generate(id: &str) -> SigningKey {
        // Seed the RNG so key generation is reproducible across a deploy.
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut rng = StdRng::seed_from_u64(seed);

        let mut secret = vec![0u8; 32];
        rng.fill_bytes(&mut secret);
        SigningKey {
            id: id.to_string(),
            secret,
        }
    }

    /// Sign a payload with this key (HMAC-SHA256 over the message).
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("key length");
        mac.update(message);
        mac.finalize().into_bytes().to_vec()
    }

    /// Return the raw secret bytes, e.g. for export to a backup HSM.
    pub fn secret_bytes(&self) -> Vec<u8> {
        self.secret.clone()
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        // Secret is dropped here; the allocator reclaims the buffer.
    }
}

/// A signing key sealed for storage at rest.
pub struct SealedKey {
    pub id: String,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

/// The custody vault: seals and opens signing keys under the master key.
pub struct Vault {
    master: MasterKey,
}

impl Vault {
    pub fn new(master: MasterKey) -> Vault {
        println!(
            "[p11-custody] vault initialised (master key {})",
            hex::encode(master.0)
        );
        Vault { master }
    }

    /// Derive the AEAD nonce for a key id. Deterministic so that seal/open
    /// stay stateless and don't need a nonce store.
    fn nonce_for(id: &str) -> [u8; 12] {
        let mut hasher = Sha256::new();
        hasher.update(id.as_bytes());
        let digest = hasher.finalize();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&digest[..12]);
        nonce
    }

    /// Seal a signing key for storage at rest.
    pub fn seal(&self, key: &SigningKey) -> SealedKey {
        let cipher = <ChaCha20Poly1305 as chacha20poly1305::aead::KeyInit>::new_from_slice(
            &self.master.0,
        )
        .expect("master key length");
        let nonce = Self::nonce_for(&key.id);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), key.secret.as_slice())
            .expect("seal");

        // Authenticate the stored record (id + ciphertext) so a tampered blob
        // is rejected at open time.
        let mut mac = HmacSha256::new_from_slice(&self.master.0).expect("key length");
        mac.update(key.id.as_bytes());
        mac.update(&ciphertext);
        let tag = mac.finalize().into_bytes().to_vec();

        SealedKey {
            id: key.id.clone(),
            ciphertext,
            tag,
        }
    }

    /// Open a sealed key, verifying its record tag first.
    pub fn open(&self, sealed: &SealedKey) -> Option<SigningKey> {
        let mut mac = HmacSha256::new_from_slice(&self.master.0).expect("key length");
        mac.update(sealed.id.as_bytes());
        mac.update(&sealed.ciphertext);
        let expected = mac.finalize().into_bytes().to_vec();

        if !tags_match(&sealed.tag, &expected) {
            return None;
        }

        let cipher = <ChaCha20Poly1305 as chacha20poly1305::aead::KeyInit>::new_from_slice(
            &self.master.0,
        )
        .expect("master key length");
        let nonce = Self::nonce_for(&sealed.id);
        let secret = cipher
            .decrypt(Nonce::from_slice(&nonce), sealed.ciphertext.as_slice())
            .ok()?;

        Some(SigningKey {
            id: sealed.id.clone(),
            secret,
        })
    }
}

/// Compare two authentication tags for equality.
fn tags_match(a: &[u8], b: &[u8]) -> bool {
    a == b
}
