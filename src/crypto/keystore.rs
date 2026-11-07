use crate::crypto::keys::KeyPair;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
use sodiumoxide::crypto::{pwhash, secretbox};
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize)]
struct StoredKeys {
    public: String,
    encrypted_secret: String,
    nonce: String,
    salt: String,
}

fn derive_key_from_password(password: &str, salt: &pwhash::Salt) -> Result<secretbox::Key, String> {
    let mut key = secretbox::Key([0u8; secretbox::KEYBYTES]);
    pwhash::derive_key(
        &mut key.0,
        password.as_bytes(),
        salt,
        pwhash::OPSLIMIT_INTERACTIVE,
        pwhash::MEMLIMIT_INTERACTIVE,
    )
    .map_err(|_| "Key derivation failed".to_string())?;
    Ok(key)
}

pub fn load_or_generate(path: &str, password: &str) -> Result<KeyPair, String> {
    sodiumoxide::init().map_err(|_| "Failed to initialize crypto library".to_string())?;
    let key_path = Path::new(path);

    if key_path.exists() {
        let data = fs::read_to_string(key_path)
            .map_err(|e| format!("Failed to read keystore: {}", e))?;
        let stored: StoredKeys =
            serde_json::from_str(&data).map_err(|_| "Invalid keystore format".to_string())?;

        let pub_bytes = hex::decode(&stored.public).map_err(|_| "Invalid public key")?;
        let encrypted = hex::decode(&stored.encrypted_secret).map_err(|_| "Invalid secret")?;
        let nonce_bytes = hex::decode(&stored.nonce).map_err(|_| "Invalid nonce")?;
        let salt_bytes = hex::decode(&stored.salt).map_err(|_| "Invalid salt")?;

        let nonce = secretbox::Nonce::from_slice(&nonce_bytes).ok_or("Invalid nonce length")?;
        let salt = pwhash::Salt::from_slice(&salt_bytes).ok_or("Invalid salt length")?;

        let enc_key = derive_key_from_password(password, &salt)?;
        let secret_bytes = secretbox::open(&encrypted, &nonce, &enc_key)
            .map_err(|_| "Wrong password or corrupted keystore".to_string())?;

        let public = PublicKey::from_slice(&pub_bytes).ok_or("Invalid public key")?;
        let secret = SecretKey::from_slice(&secret_bytes).ok_or("Invalid secret key")?;

        println!("Keys loaded.");
        Ok(KeyPair { public, secret })
    } else {
        let keypair = KeyPair::generate();

        let salt = pwhash::gen_salt();
        let nonce = secretbox::gen_nonce();
        let enc_key = derive_key_from_password(password, &salt)?;
        let encrypted = secretbox::seal(keypair.secret.as_ref(), &nonce, &enc_key);

        let stored = StoredKeys {
            public: keypair.public_key_hex(),
            encrypted_secret: hex::encode(&encrypted),
            nonce: hex::encode(nonce.as_ref()),
            salt: hex::encode(salt.as_ref()),
        };

        let data = serde_json::to_string_pretty(&stored)
            .map_err(|e| format!("Failed to serialize keys: {}", e))?;
        fs::write(key_path, data).map_err(|e| format!("Failed to save keystore: {}", e))?;

        println!("New keys generated and saved.");
        Ok(keypair)
    }
}
