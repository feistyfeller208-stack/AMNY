use sha2::{Digest, Sha256};
use sharks::{Share, Sharks};

use crate::crypto::encryption::Encryption;
use crate::henzi::fragment::derive_position;

pub const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4MB
pub const TOTAL_SHARES: u8 = 5;
pub const THRESHOLD: u8 = 3;
pub const DEFAULT_TTL_SECS: u64 = 72 * 60 * 60; // 72 hours
pub const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024 * 1024; // 100GB
const MAX_NAME_BYTES: usize = 200;

pub struct EncodedFragment {
    pub fragment_index: u8,
    pub position: String,
    pub data: Vec<u8>,
}

pub struct DecodedChunk {
    pub total_chunks: u32,
    pub transfer_id: [u8; 32],
    pub filename: String,
    pub data: Vec<u8>,
}

pub struct HenziTrace;

impl HenziTrace {
    pub fn chunk_count(file_size: u64) -> u32 {
        ((file_size + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64) as u32
    }

    pub fn derive_file_id(shared_secret: &[u8], sender_public_hex: &str, sequence: u64) -> String {
        let mut h = Sha256::new();
        h.update(b"amny-fid-v2");
        h.update(shared_secret);
        h.update(sender_public_hex.as_bytes());
        h.update(sequence.to_le_bytes());
        hex::encode(h.finalize())[..16].to_string()
    }

    pub fn encode_chunk(
        chunk: &[u8],
        chunk_index: u32,
        total_chunks: u32,
        filename: &str,
        shared_secret: &[u8],
        file_id: &str,
        transfer_id: &[u8; 32],
    ) -> Result<Vec<EncodedFragment>, String> {
        if chunk.is_empty() {
            return Err("Cannot encode an empty chunk".to_string());
        }
        let key = Encryption::derive_key(shared_secret, file_id);
        let name = truncate_name(filename);
        let mut out = Vec::with_capacity(TOTAL_SHARES as usize);

        for (i, share) in Sharks(THRESHOLD)
            .dealer(chunk)
            .take(TOTAL_SHARES as usize)
            .enumerate()
        {
            let share_bytes: Vec<u8> = (&share).into();

            // Header: [total_chunks(4)][transfer_id(32)][name_len(1)][name][share_bytes]
            let mut plain = Vec::with_capacity(4 + 32 + 1 + name.len() + share_bytes.len());
            plain.extend_from_slice(&total_chunks.to_le_bytes());
            plain.extend_from_slice(transfer_id);
            plain.push(name.len() as u8);
            plain.extend_from_slice(name.as_bytes());
            plain.extend_from_slice(&share_bytes);

            let fragment_index = i as u8;
            let position = derive_position(shared_secret, file_id, chunk_index, fragment_index);
            let data = Encryption::encrypt(&plain, &key, position.as_bytes())?;

            out.push(EncodedFragment {
                fragment_index,
                position,
                data,
            });
        }
        Ok(out)
    }

    pub fn decode_chunk(
        parts: &[(String, Vec<u8>)],
        shared_secret: &[u8],
        file_id: &str,
    ) -> Result<DecodedChunk, String> {
        let key = Encryption::derive_key(shared_secret, file_id);
        let mut shares: Vec<Share> = Vec::new();
        let mut header: Option<(u32, [u8; 32], String)> = None;
        let mut bad = 0usize;

        for (position, data) in parts {
            if shares.len() >= THRESHOLD as usize {
                break;
            }
            let plain = match Encryption::decrypt(data, &key, position.as_bytes()) {
                Ok(p) => p,
                Err(_) => {
                    bad += 1;
                    continue;
                }
            };
            let (total, t_id, name, share_bytes) = match parse_plain(&plain) {
                Ok(v) => v,
                Err(_) => {
                    bad += 1;
                    continue;
                }
            };
            match &header {
                None => header = Some((total, t_id, name)),
                Some((t, t_id_h, n)) => {
                    if *t != total || *t_id_h != t_id || *n != name {
                        return Err("Fragments disagree about the file they belong to".to_string());
                    }
                }
            }
            match Share::try_from(share_bytes) {
                Ok(s) => shares.push(s),
                Err(_) => bad += 1,
            }
        }

        if shares.len() < THRESHOLD as usize {
            return Err(format!(
                "Only {} usable fragments ({} failed to decrypt), need {}",
                shares.len(),
                bad,
                THRESHOLD
            ));
        }

        let (total_chunks, transfer_id, filename) = header.ok_or("No header found")?;
        let data = Sharks(THRESHOLD)
            .recover(&shares)
            .map_err(|e| format!("Shamir reconstruction failed: {}", e))?;

        Ok(DecodedChunk {
            total_chunks,
            transfer_id,
            filename,
            data,
        })
    }
}

fn truncate_name(name: &str) -> String {
    let mut end = name.len().min(MAX_NAME_BYTES);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    name[..end].to_string()
}

fn parse_plain(plain: &[u8]) -> Result<(u32, [u8; 32], String, &[u8]), String> {
    if plain.len() < 4 + 32 + 1 {
        return Err("Header too short".to_string());
    }
    let total = u32::from_le_bytes([plain[0], plain[1], plain[2], plain[3]]);
    
    let mut t_id = [0u8; 32];
    t_id.copy_from_slice(&plain[4..36]);
    
    let name_len = plain[36] as usize;
    if plain.len() < 37 + name_len + 1 {
        return Err("Header truncated".to_string());
    }
    let name = std::str::from_utf8(&plain[37..37 + name_len])
        .map_err(|_| "Filename is not valid UTF-8".to_string())?
        .to_string();
    Ok((total, t_id, name, &plain[37 + name_len..]))
}