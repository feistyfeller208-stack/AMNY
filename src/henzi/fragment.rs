use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub const FRAGMENT_VERSION: u8 = 2;

/// What a node stores. Nothing else: no file id, no chunk number, no owner.
#[derive(Debug, Clone)]
pub struct Fragment {
    pub version: u8,
    pub expires_at: u64,
    pub token_hash: [u8; 32], // <--- Stores the hash, not the raw token
    pub data: Vec<u8>,
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn derive_position(
    shared_secret: &[u8],
    file_id: &str,
    chunk_index: u32,
    fragment_index: u8,
) -> String {
    let mut h = Sha256::new();
    h.update(b"amny-pos-v1");
    h.update(shared_secret);
    h.update(file_id.as_bytes());
    h.update(chunk_index.to_le_bytes());
    h.update([fragment_index]);
    hex::encode(h.finalize())
}

pub fn derive_delete_token(shared_secret: &[u8], position: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"amny-del-v1");
    h.update(shared_secret);
    h.update(position.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

pub fn is_valid_position(p: &str) -> bool {
    p.len() == 64 && p.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn node_id(public_key: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(public_key));
    out
}

pub fn position_bytes(position: &str) -> Option<[u8; 32]> {
    let v = hex::decode(position).ok()?;
    <[u8; 32]>::try_from(v.as_slice()).ok()
}

pub fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}