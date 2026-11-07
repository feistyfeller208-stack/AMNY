use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use sha2::{Digest, Sha256};

use crate::crypto::keys::SharedSecret;
use crate::henzi::fragment::{derive_position, derive_delete_token, now_secs, Fragment, FRAGMENT_VERSION};
use crate::henzi::trace::{
    HenziTrace, DEFAULT_TTL_SECS, CHUNK_SIZE, MAX_FILE_SIZE, THRESHOLD, TOTAL_SHARES,
};
use crate::network::nodes::Holder;
use crate::node::runtime::{Node, Pool};

pub const REPLICAS: usize = 3;
pub const MAX_PROBE_HOLDERS: usize = 6;
pub const SEQUENCE_WINDOW: u64 = 10;

#[derive(Serialize, Deserialize, Default, Clone, Copy)]
pub struct Counter { pub sent: u64, pub received: u64 }

#[derive(Serialize, Deserialize, Default)]
pub struct Sequences { counters: HashMap<String, Counter> }

impl Sequences {
    pub fn load(path: &Path) -> Self {
        fs::read_to_string(path).ok().and_then(|d| serde_json::from_str(&d).ok()).unwrap_or_default()
    }
    pub fn save(&self, path: &Path) {
        if let Ok(d) = serde_json::to_string_pretty(self) { let _ = fs::write(path, d); }
    }
    pub fn get(&self, contact_hex: &str) -> Counter { self.counters.get(contact_hex).copied().unwrap_or_default() }
    pub fn set_sent(&mut self, contact_hex: &str, n: u64) { self.counters.entry(contact_hex.to_string()).or_default().sent = n; }
    pub fn set_received(&mut self, contact_hex: &str, n: u64) { self.counters.entry(contact_hex.to_string()).or_default().received = n; }
}

fn shared_with(contact_hex: &str, our_secret: &SecretKey) -> Result<SharedSecret, String> {
    let bytes = hex::decode(contact_hex).map_err(|_| "Invalid contact public key".to_string())?;
    let their_public = PublicKey::from_slice(&bytes).ok_or("Invalid public key length")?;
    Ok(SharedSecret::derive(our_secret, &their_public))
}

pub fn sanitize_filename(name: &str) -> String {
    let last = name.rsplit(|c| c == '/' || c == '\\').next().unwrap_or("");
    let cleaned: String = last.chars().filter(|c| !c.is_control() && !"<>:\"|?*".contains(*c)).collect();
    let cleaned = cleaned.trim().trim_matches('.').trim().to_string();
    if cleaned.is_empty() { return "received.bin".to_string(); }
    let stem = cleaned.split('.').next().unwrap_or("").to_uppercase();
    let reserved = ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
        || (stem.len() == 4 && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.chars().last().map(|c| c.is_ascii_digit() && c != '0').unwrap_or(false));
    if reserved { format!("_{}", cleaned) } else { cleaned }
}

fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !first.exists() { return first; }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{}", e)),
        _ => (name.to_string(), String::new()),
    };
    for i in 1..10_000 {
        let candidate = dir.join(format!("{} ({}){}", stem, i, ext));
        if !candidate.exists() { return candidate; }
    }
    first
}

pub struct SendReport {
    pub file_id: String, pub chunks: u32, pub fragments: usize, pub bytes: u64,
    pub min_replicas: usize, pub min_remote_replicas: usize,
}

fn place_fragment(node: &Node, pool: &mut Pool, position: &str, frag: &Fragment) -> Result<(usize, usize), String> {
    let mut total = 0; let mut remote = 0; let mut last_err = "no node was reachable".to_string();
    for holder in node.ranked(position) {
        if total >= REPLICAS { break; }
        match node.put_at(pool, &holder, position, frag) {
            Ok(()) => {
                total += 1;
                if matches!(holder, Holder::Remote(_)) { remote += 1; }
            }
            Err(e) => last_err = e,
        }
    }
    if total == 0 { Err(last_err) } else { Ok((total, remote)) }
}

fn estimate_bytes_per_node(file_size: u64, known_others: usize) -> u64 {
    let nodes = known_others as u64 + 1;
    let holders = nodes.min(REPLICAS as u64);
    (TOTAL_SHARES as u64 * file_size * holders) / nodes
}

pub fn send_file(
    node: &Node, our_secret: &SecretKey, contact_hex: &str, path: &Path, sequence: u64, progress: &mut dyn FnMut(&str),
) -> Result<SendReport, String> {
    if !path.is_file() { return Err(format!("File not found: {}", path.display())); }
    let size = fs::metadata(path).map_err(|e| format!("Cannot read file: {}", e))?.len();
    if size == 0 { return Err("File is empty".to_string()); }
    if size > MAX_FILE_SIZE { return Err("File exceeds the maximum allowed size".to_string()); }

    let needed = estimate_bytes_per_node(size, node.known_nodes().len());
    let free = node.store_free_bytes();
    if needed > free {
        let mb = |b: u64| b / (1024 * 1024);
        return Err(format!(
            "Not enough room. This file needs about {} MB on each node that keeps it \
             and this node has {} MB free of its {} MB limit.\n\
             Options: send a smaller file, add more nodes so the load is shared, \
             free space by removing old fragments, or raise this node's limit by typing: limit <MB>",
            mb(needed), mb(free), mb(node.store_limit_bytes())
        ));
    }

    let shared = shared_with(contact_hex, our_secret)?;
    let file_id = HenziTrace::derive_file_id(shared.as_bytes(), &node.my_hex, sequence);
    
    let mut transfer_id = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut transfer_id);

    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("file").to_string();
    let total_chunks = HenziTrace::chunk_count(size);
    let expires_at = now_secs() + DEFAULT_TTL_SECS;

    let mut file = fs::File::open(path).map_err(|e| format!("Cannot open file: {}", e))?;
    let mut pool = Pool::new();
    let mut placed: Vec<(String, [u8; 32])> = Vec::new();
    let mut fragments = 0usize;
    let mut min_replicas = usize::MAX;
    let mut min_remote = usize::MAX;

    let outcome: Result<(), String> = (|| {
        let order: Vec<u32> = (1..total_chunks).chain(std::iter::once(0)).collect();
        for (done, &chunk_index) in order.iter().enumerate() {
            let offset = chunk_index as u64 * CHUNK_SIZE as u64;
            let expected = (size - offset).min(CHUNK_SIZE as u64) as usize;
            file.seek(SeekFrom::Start(offset)).map_err(|e| format!("Read error: {}", e))?;
            let mut buf = Vec::with_capacity(expected);
            (&mut file).take(expected as u64).read_to_end(&mut buf).map_err(|e| format!("Read error: {}", e))?;
            if buf.len() != expected { return Err("The file changed while it was being sent".to_string()); }

            let encoded = HenziTrace::encode_chunk(
                &buf, chunk_index, total_chunks, &filename, shared.as_bytes(), &file_id, &transfer_id,
            )?;
            drop(buf);

            for ef in encoded {
                let raw_token = derive_delete_token(shared.as_bytes(), &ef.position);
                let mut token_hash = [0u8; 32];
                token_hash.copy_from_slice(&Sha256::digest(&raw_token));

                let frag = Fragment { 
                    version: FRAGMENT_VERSION, 
                    expires_at, 
                    token_hash,
                    data: ef.data 
                };
                let (total, remote) = place_fragment(node, &mut pool, &ef.position, &frag)
                    .map_err(|reason| format!("Could not store fragment {} of chunk {}: {}", ef.fragment_index, chunk_index + 1, reason))?;
                
                placed.push((ef.position, raw_token)); 
                min_replicas = min_replicas.min(total);
                min_remote = min_remote.min(remote);
                fragments += 1;
            }
            progress(&format!("  chunk {}/{} placed", done + 1, total_chunks));
        }
        Ok(())
    })();

    if let Err(e) = outcome {
        for (position, token) in &placed {
            for holder in node.ranked(position).into_iter().take(MAX_PROBE_HOLDERS) {
                let _ = node.delete_at(&mut pool, &holder, position, token);
            }
        }
        return Err(format!("{}\nThe fragments already placed were removed.", e));
    }

    Ok(SendReport {
        file_id, chunks: total_chunks, fragments, bytes: size, min_replicas, min_remote_replicas: min_remote,
    })
}

pub struct ReceiveReport {
    pub saved_to: PathBuf, pub filename: String, pub bytes: u64, pub sequence: u64,
}

fn fetch_chunk(
    node: &Node,
    pool: &mut Pool,
    shared: &[u8],
    file_id: &str,
    chunk_index: u32,
    want: usize,
) -> Vec<(String, Vec<u8>)> {
    let mut found: Vec<(String, Vec<u8>)> = Vec::new();
    for fragment_index in 0..TOTAL_SHARES {
        if found.len() >= want {
            break;
        }
        let position = derive_position(shared, file_id, chunk_index, fragment_index);
        
        // Try each holder in order of distance until one gives us a valid fragment
        for holder in node.ranked(&position).into_iter().take(MAX_PROBE_HOLDERS) {
            if let Ok(Some(frag)) = node.get_at(pool, &holder, &position) {
                
                // N8 Fix: Test the data BEFORE accepting it.
                // We use a dummy 32-byte array as the AAD (which is the position) for the decryption test.
                let mut check_frag = frag.clone();
                check_frag.token_hash = [0u8; 32]; // We don't care about the token for decryption
                let key = crate::crypto::encryption::Encryption::derive_key(shared, file_id);
                
                // If it decrypts, it's a real fragment. Keep it.
                if crate::crypto::encryption::Encryption::decrypt(&frag.data, &key, position.as_bytes()).is_ok() {
                    found.push((position.clone(), frag.data));
                    break; // We got a good one, move to the next fragment index
                }
                // If it fails to decrypt, we just don't break. The loop continues to the next holder.
            }
        }
    }
    found
}

fn fetch_and_decode(node: &Node, pool: &mut Pool, shared: &[u8], file_id: &str, chunk_index: u32) -> Result<Option<crate::henzi::trace::DecodedChunk>, String> {
    let parts = fetch_chunk(node, pool, shared, file_id, chunk_index, THRESHOLD as usize);
    if parts.is_empty() { return Ok(None); }
    if parts.len() >= THRESHOLD as usize {
        if let Ok(chunk) = HenziTrace::decode_chunk(&parts, shared, file_id) { return Ok(Some(chunk)); }
    }
    let parts = fetch_chunk(node, pool, shared, file_id, chunk_index, TOTAL_SHARES as usize);
    if parts.len() < THRESHOLD as usize {
        return Err(format!("Chunk {}: only {} of {} fragments reachable.", chunk_index + 1, parts.len(), THRESHOLD));
    }
    HenziTrace::decode_chunk(&parts, shared, file_id).map(Some).map_err(|e| format!("Chunk {}: {}", chunk_index + 1, e))
}

pub fn receive_next(
    node: &Node, our_secret: &SecretKey, contact_hex: &str, start_sequence: u64, out_dir: &Path, name_override: Option<&str>, progress: &mut dyn FnMut(&str),
) -> Result<Option<ReceiveReport>, String> {
    let shared = shared_with(contact_hex, our_secret)?;
    let mut pool = Pool::new();

    for sequence in start_sequence..start_sequence + SEQUENCE_WINDOW {
        let file_id = HenziTrace::derive_file_id(shared.as_bytes(), contact_hex, sequence);
        let first = match fetch_and_decode(node, &mut pool, shared.as_bytes(), &file_id, 0)? {
            Some(c) => c, None => continue,
        };

        let total = first.total_chunks;
        let max_chunks = HenziTrace::chunk_count(MAX_FILE_SIZE);
        if total == 0 || total > max_chunks { return Err("The file header is invalid".to_string()); }

        let name = match name_override {
            Some(n) if !n.trim().is_empty() => sanitize_filename(n),
            _ => sanitize_filename(&first.filename),
        };
        fs::create_dir_all(out_dir).map_err(|e| format!("Cannot create output folder: {}", e))?;
        let final_path = unique_path(out_dir, &name);
        let part_path = PathBuf::from(format!("{}.part", final_path.display()));

        let result = (|| -> Result<u64, String> {
            let mut out = fs::File::create(&part_path).map_err(|e| format!("Cannot create output file: {}", e))?;
            let mut written = 0u64;
            out.write_all(&first.data).map_err(|e| format!("Write error: {}", e))?;
            written += first.data.len() as u64;
            progress(&format!("  chunk 1/{} collected", total));

            for chunk_index in 1..total {
                let chunk = fetch_and_decode(node, &mut pool, shared.as_bytes(), &file_id, chunk_index)?
                    .ok_or(format!("Chunk {} of {} is missing.", chunk_index + 1, total))?;
                
                // N1 Fix: Detect mixed chunks from different sends
                if chunk.total_chunks != total { 
                    return Err("Chunks disagree about the file length".to_string()); 
                }
                if chunk.transfer_id != first.transfer_id {
                    return Err("Security: Detected a chunk from a different send attempt. Aborting.".to_string());
                }

                out.write_all(&chunk.data).map_err(|e| format!("Write error: {}", e))?;
                written += chunk.data.len() as u64;
                progress(&format!("  chunk {}/{} collected", chunk_index + 1, total));
            }
            out.flush().map_err(|e| format!("Write error: {}", e))?;
            Ok(written)
        })();

        let bytes = match result {
            Ok(b) => b,
            Err(e) => { let _ = fs::remove_file(&part_path); return Err(e); }
        };
        fs::rename(&part_path, &final_path).map_err(|e| format!("Cannot save file: {}", e))?;

        for chunk_index in 0..total {
            for fragment_index in 0..TOTAL_SHARES {
                let position = derive_position(shared.as_bytes(), &file_id, chunk_index, fragment_index);
                let raw_token = derive_delete_token(shared.as_bytes(), &position); 
                for holder in node.ranked(&position).into_iter().take(MAX_PROBE_HOLDERS) {
                    let _ = node.delete_at(&mut pool, &holder, &position, &raw_token);
                }
            }
        }

        return Ok(Some(ReceiveReport { saved_to: final_path, filename: name, bytes, sequence }));
    }
    Ok(None)
}