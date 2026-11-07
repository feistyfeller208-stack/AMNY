use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

pub const MAX_HEADER: usize = 64 * 1024;
pub const MAX_BODY: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerWire {
    pub public_key: String,
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Message {
    Announce { 
        public_key: String, 
        port: u16,
        advertised_addr: Option<String>, 
    },
    Welcome { 
        public_key: String, 
        peers: Vec<PeerWire>,
        advertised_addr: Option<String>, 
    },
    Put { 
        position: String, 
        version: u8, 
        expires_at: u64,
        token_hash: [u8; 32],
    },
    Get { position: String },
    Found { version: u8, expires_at: u64 },
    NotFound,
    Delete { 
        position: String,
        token: [u8; 32],
    },
    Ack,
    Error { message: String },
}

pub fn write_frame<W: Write>(w: &mut W, msg: &Message, body: &[u8]) -> Result<(), String> {
    let header = serde_json::to_vec(msg).map_err(|e| format!("Serialization error: {}", e))?;
    if header.len() > MAX_HEADER || body.len() > MAX_BODY {
        return Err("Frame too large".to_string());
    }
    let mut head = Vec::with_capacity(8 + header.len());
    head.extend_from_slice(&(header.len() as u32).to_be_bytes());
    head.extend_from_slice(&header);
    head.extend_from_slice(&(body.len() as u32).to_be_bytes());
    w.write_all(&head).map_err(|e| format!("Write error: {}", e))?;
    if !body.is_empty() {
        w.write_all(body).map_err(|e| format!("Write error: {}", e))?;
    }
    w.flush().map_err(|e| format!("Flush error: {}", e))
}

pub fn read_frame<R: Read>(r: &mut R) -> Result<(Message, Vec<u8>), String> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).map_err(|_| "Connection closed".to_string())?;
    let hlen = u32::from_be_bytes(len) as usize;
    if hlen == 0 || hlen > MAX_HEADER {
        return Err("Bad header length".to_string());
    }
    let mut header = vec![0u8; hlen];
    r.read_exact(&mut header).map_err(|_| "Connection closed".to_string())?;

    r.read_exact(&mut len).map_err(|_| "Connection closed".to_string())?;
    let blen = u32::from_be_bytes(len) as usize;
    if blen > MAX_BODY {
        return Err("Body too large".to_string());
    }
    let mut body = vec![0u8; blen];
    r.read_exact(&mut body).map_err(|_| "Connection closed".to_string())?;

    let msg = serde_json::from_slice(&header).map_err(|_| "Bad message".to_string())?;
    Ok((msg, body))
}