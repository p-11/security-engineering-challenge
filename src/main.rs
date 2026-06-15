//! Tiny demo runner for the p11-custody service.
//!
//! Run with `cargo run --bin p11-demo`.

use p11_custody::{MasterKey, SigningKey, Vault};

fn main() {
    // Load the vault master key and bring up the custody service.
    let master = MasterKey::load();
    let vault = Vault::new(master);

    // Provision a signing key for a customer and seal it for storage.
    let key = SigningKey::generate("acct-4417");
    println!("[demo] generated signing key: {:?}", key);

    let sealed = vault.seal(&key);
    println!(
        "[demo] sealed {} ({} bytes ciphertext)",
        sealed.id,
        sealed.ciphertext.len()
    );

    // Later: open the sealed key and use it to sign a settlement payload.
    let restored = vault.open(&sealed).expect("open sealed key");
    let signature = restored.sign(b"transfer 5 BTC to acct-9001");
    println!("[demo] signature: {}", hex::encode(signature));
}
