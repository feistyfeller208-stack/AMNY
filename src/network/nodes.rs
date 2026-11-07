use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::henzi::fragment::{node_id, now_secs, position_bytes, xor_distance};
use crate::network::protocol::PeerWire;

pub const MAX_NODES: usize = 256;
const MAX_FAILURES: u32 = 3;
const MAX_PEERS_PER_MESSAGE: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeEntry {
    pub public_key: String,
    pub ip: String, // Changed from IpAddr to String to allow hostnames (e.g. ngrok.io)
    pub port: u16,
    pub last_seen: u64,
    #[serde(default)]
    pub failures: u32,
}

impl NodeEntry {
    pub fn new(public_key: String, ip: String, port: u16) -> Self {
        NodeEntry {
            public_key: public_key.to_lowercase(),
            ip,
            port,
            last_seen: now_secs(),
            failures: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Holder {
    Local,
    Remote(NodeEntry),
}

#[derive(Serialize, Deserialize, Default)]
struct NodesFile {
    bootstrap: Option<String>,
    nodes: Vec<NodeEntry>,
}

pub struct NodeTable {
    my_key: String,
    my_id: [u8; 32],
    nodes: HashMap<String, NodeEntry>,
    pub bootstrap: Option<String>,
}

pub fn valid_key(k: &str) -> bool {
    k.len() == 64 && k.bytes().all(|b| b.is_ascii_hexdigit())
}

impl NodeTable {
    pub fn new(my_key: &str) -> Self {
        let my_id = hex::decode(my_key)
            .map(|b| node_id(&b))
            .unwrap_or([0u8; 32]);
        NodeTable {
            my_key: my_key.to_lowercase(),
            my_id,
            nodes: HashMap::new(),
            bootstrap: None,
        }
    }

    pub fn load(path: &Path, my_key: &str) -> Self {
        let mut table = NodeTable::new(my_key);
        if let Ok(data) = fs::read_to_string(path) {
            if let Ok(file) = serde_json::from_str::<NodesFile>(&data) {
                table.bootstrap = file.bootstrap;
                for e in file.nodes {
                    table.upsert_direct(e);
                }
            }
        }
        table
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let file = NodesFile {
            bootstrap: self.bootstrap.clone(),
            nodes: self.nodes.values().cloned().collect(),
        };
        let data = serde_json::to_string_pretty(&file).map_err(|e| e.to_string())?;
        fs::write(path, data).map_err(|e| format!("Failed to save node list: {}", e))
    }

    fn acceptable(&self, e: &NodeEntry) -> bool {
        valid_key(&e.public_key)
            && e.public_key != self.my_key
            && e.port != 0
            && !e.ip.is_empty()
            && (self.nodes.contains_key(&e.public_key) || self.nodes.len() < MAX_NODES)
    }

    pub fn upsert_direct(&mut self, mut e: NodeEntry) -> bool {
        e.public_key = e.public_key.to_lowercase();
        if !self.acceptable(&e) {
            return false;
        }
        e.failures = 0;
        e.last_seen = now_secs();
        self.nodes.insert(e.public_key.clone(), e);
        true
    }

    pub fn learn(&mut self, mut e: NodeEntry) -> bool {
        e.public_key = e.public_key.to_lowercase();
        if self.nodes.contains_key(&e.public_key) || !self.acceptable(&e) {
            return false;
        }
        self.nodes.insert(e.public_key.clone(), e);
        true
    }

    /// Merges a peer list received from `via_host`. 
    /// If a peer sends its IP as loopback (127.0.0.1) and the connection didn't come 
    /// from loopback, we replace it with the host that told us about it.
    pub fn merge_wire_peers(&mut self, peers: Vec<PeerWire>, via_host: &str) {
        let via_loopback = via_host.eq_ignore_ascii_case("localhost") 
            || via_host == "127.0.0.1" 
            || via_host == "::1";

        for p in peers.into_iter().take(MAX_PEERS_PER_MESSAGE) {
            let ip_str = if (p.ip == "127.0.0.1" || p.ip == "::1") && !via_loopback {
                via_host.to_string()
            } else {
                p.ip
            };
            self.learn(NodeEntry::new(p.public_key, ip_str, p.port));
        }
    }

    pub fn mark_failed(&mut self, key: &str) {
        let remove = match self.nodes.get_mut(key) {
            Some(e) => {
                e.failures += 1;
                e.failures >= MAX_FAILURES
            }
            None => false,
        };
        if remove {
            self.nodes.remove(key);
        }
    }

    pub fn entries(&self) -> Vec<NodeEntry> {
        let mut v: Vec<NodeEntry> = self.nodes.values().cloned().collect();
        v.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        v
    }

    pub fn wire_entries(&self, exclude_key: &str) -> Vec<PeerWire> {
        self.nodes
            .values()
            .filter(|e| e.public_key != exclude_key.to_lowercase())
            .take(MAX_PEERS_PER_MESSAGE)
            .map(|e| PeerWire {
                public_key: e.public_key.clone(),
                ip: e.ip.clone(),
                port: e.port,
            })
            .collect()
    }

    pub fn count(&self) -> usize {
        self.nodes.len()
    }

    pub fn ranked(&self, position: &str) -> Vec<Holder> {
        let target = match position_bytes(position) {
            Some(t) => t,
            None => return vec![Holder::Local],
        };
        let mut items: Vec<([u8; 32], Holder)> = Vec::with_capacity(self.nodes.len() + 1);
        items.push((xor_distance(&self.my_id, &target), Holder::Local));
        for e in self.nodes.values() {
            if let Ok(pk) = hex::decode(&e.public_key) {
                items.push((xor_distance(&node_id(&pk), &target), Holder::Remote(e.clone())));
            }
        }
        items.sort_by(|a, b| a.0.cmp(&b.0));
        items.into_iter().map(|(_, h)| h).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> String {
        hex::encode([n; 32])
    }

    #[test]
    fn loopback_peers_are_rewritten_to_the_host_that_told_us() {
        let mut t = NodeTable::new(&key(1));
        let peers = vec![PeerWire { public_key: key(2), ip: "127.0.0.1".into(), port: 7778 }];
        t.merge_wire_peers(peers, "192.168.100.66");
        let e = t.entries();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].ip, "192.168.100.66");
        assert_eq!(e[0].port, 7778);
    }

    #[test]
    fn loopback_stays_loopback_when_told_by_a_loopback_host() {
        let mut t = NodeTable::new(&key(1));
        let peers = vec![PeerWire { public_key: key(2), ip: "127.0.0.1".into(), port: 7778 }];
        t.merge_wire_peers(peers, "127.0.0.1");
        assert_eq!(t.entries()[0].ip, "127.0.0.1");
    }

    #[test]
    fn gossip_cannot_overwrite_a_node_we_met_directly() {
        let mut t = NodeTable::new(&key(1));
        t.upsert_direct(NodeEntry::new(key(2), "10.0.0.5".into(), 7777));
        let liar = vec![PeerWire { public_key: key(2), ip: "6.6.6.6".into(), port: 1 }];
        t.merge_wire_peers(liar, "10.0.0.9");
        assert_eq!(t.entries()[0].ip, "10.0.0.5");
    }

    #[test]
    fn a_node_never_lists_itself_and_rejects_bad_keys() {
        let mut t = NodeTable::new(&key(1));
        assert!(!t.upsert_direct(NodeEntry::new(key(1), "10.0.0.1".into(), 7777)));
        assert!(!t.upsert_direct(NodeEntry::new("nothex".into(), "10.0.0.1".into(), 7777)));
        assert!(!t.upsert_direct(NodeEntry::new(key(3), "10.0.0.1".into(), 0)));
    }

    #[test]
    fn ranking_is_deterministic_and_includes_us() {
        let mut t = NodeTable::new(&key(1));
        t.upsert_direct(NodeEntry::new(key(2), "10.0.0.2".into(), 7777));
        t.upsert_direct(NodeEntry::new(key(3), "10.0.0.3".into(), 7777));
        let pos = hex::encode([9u8; 32]);
        let a = t.ranked(&pos);
        let b = t.ranked(&pos);
        assert_eq!(a.len(), 3);
        assert_eq!(format!("{:?}", a), format!("{:?}", b));
        assert!(a.iter().any(|h| matches!(h, Holder::Local)));
    }
}