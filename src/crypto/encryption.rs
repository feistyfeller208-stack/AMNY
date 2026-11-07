use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng, Payload},
    Aes256Gcm, Key, Nonce,
};
use sha2::{Digest, Sha256};

pub struct Encryption;

impl Encryption {
    pub fn derive_key(shared_secret: &[u8], file_id: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"amny-key-v1");
        hasher.update(shared_secret);
        hasher.update(file_id.as_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&hasher.finalize());
        key
    }

    /// `aad` is the fragment's position. It is authenticated but not stored, so a
    /// node cannot answer a request for one position with a fragment from another.
    pub fn encrypt(plaintext: &[u8], key_bytes: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: plaintext, aad })
            .map_err(|e| format!("Encryption failed: {}", e))?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt(data: &[u8], key_bytes: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 12 {
            return Err("Data too short, missing nonce".to_string());
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));
        cipher
            .decrypt(Nonce::from_slice(nonce_bytes), Payload { msg: ciphertext, aad })
            .map_err(|_| "Decryption failed (wrong key, wrong position, or tampered data)".to_string())
    }
}
