use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::henzi::fragment::{is_valid_position, now_secs, Fragment, FRAGMENT_VERSION};
use crate::network::nodes::{valid_key, Holder, NodeEntry, NodeTable};
use crate::network::protocol::{read_frame, write_frame, Message};

pub const DEFAULT_PORT: u16 = 7777;
pub const DEFAULT_MAX_STORE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_TTL_SECS: u64 = 30 * 24 * 60 * 60;
const GOSSIP_INTERVAL_SECS: u64 = 15;
const MAX_GOSSIP_PER_ROUND: usize = 16;
const HEADER_SIZE: usize = 1 + 8 + 32; // version + expires_at + token_hash

#[derive(Serialize, Deserialize, Default)]
struct Settings {
    store_limit_bytes: Option<u64>,
    advertised_addr: Option<String>,
}

fn load_settings(dir: &std::path::Path) -> Settings {
    fs::read_to_string(dir.join("settings.json"))
        .ok()
        .and_then(|d| serde_json::from_str(&d).ok())
        .unwrap_or_default()
}

pub struct FragmentStore {
    dir: PathBuf,
    index: HashMap<String, (u64, u64)>, 
    bytes: u64,
    max_bytes: u64,
}

impl FragmentStore {
    pub fn open(dir: PathBuf, max_bytes: u64) -> Result<Self, String> {
        fs::create_dir_all(&dir).map_err(|e| format!("Cannot create fragment folder: {}", e))?;
        let mut index = HashMap::new();
        let mut bytes = 0u64;

        let entries = fs::read_dir(&dir).map_err(|e| format!("Cannot read fragment folder: {}", e))?;
        for entry in entries.flatten() {
            let path = entry.path();
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            if name.ends_with(".tmp") {
                let _ = fs::remove_file(&path);
                continue;
            }
            let position = match name.strip_suffix(".frag") {
                Some(p) if is_valid_position(p) => p.to_string(),
                _ => {
                    let _ = fs::remove_file(&path); 
                    continue;
                }
            };
            
            let mut head = [0u8; HEADER_SIZE];
            if fs::File::open(&path).and_then(|mut f| f.read_exact(&mut head)).is_err() {
                let _ = fs::remove_file(&path); 
                continue;
            }
            
            let version = head[0];
            let expires = u64::from_be_bytes(head[1..9].try_into().unwrap());
            
            if version != FRAGMENT_VERSION || expires > now_secs() + MAX_TTL_SECS {
                let _ = fs::remove_file(&path);
                continue;
            }

            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            index.insert(position, (expires, size));
            bytes += size;
        }
        Ok(FragmentStore { dir, index, bytes, max_bytes })
    }

    fn path_for(&self, position: &str) -> PathBuf {
        self.dir.join(format!("{}.frag", position))
    }

    pub fn put(&mut self, position: &str, f: &Fragment) -> Result<(), String> {
        if !is_valid_position(position) {
            return Err("Invalid position".to_string());
        }
        let new_size = HEADER_SIZE as u64 + f.data.len() as u64;
        let old_size = self.index.get(position).map(|(_, s)| *s).unwrap_or(0);
        
        if self.index.contains_key(position) {
            if let Some(existing) = self.get(position) {
                if existing.data == f.data {
                    return Ok(()); 
                } else {
                    return Err("Position is already occupied by a live fragment".to_string());
                }
            }
        }

        if self.bytes - old_size + new_size > self.max_bytes {
            return Err("Store full".to_string());
        }

        let tmp = self.dir.join(format!("{}.tmp", position));
        let write = || -> std::io::Result<()> {
            let mut file = fs::File::create(&tmp)?;
            file.write_all(&[f.version])?;
            file.write_all(&f.expires_at.to_be_bytes())?;
            file.write_all(&f.token_hash)?;
            file.write_all(&f.data)?;
            file.flush()?;
            Ok(())
        };
        if let Err(e) = write() {
            let _ = fs::remove_file(&tmp);
            return Err(format!("Disk write failed: {}", e));
        }
        fs::rename(&tmp, self.path_for(position)).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            format!("Disk write failed: {}", e)
        })?;

        self.bytes = self.bytes - old_size + new_size;
        self.index.insert(position.to_string(), (f.expires_at, new_size));
        Ok(())
    }

    pub fn get(&self, position: &str) -> Option<Fragment> {
        if !is_valid_position(position) {
            return None;
        }
        let (expires, _) = *self.index.get(position)?;
        if expires < now_secs() {
            return None;
        }
        let mut data = fs::read(self.path_for(position)).ok()?;
        if data.len() < HEADER_SIZE {
            return None;
        }
        
        let version = data[0];
        let expires_at = u64::from_be_bytes(data[1..9].try_into().ok()?);
        let mut token_hash = [0u8; 32];
        token_hash.copy_from_slice(&data[9..41]);
        
        let body = data.split_off(HEADER_SIZE);
        
        Some(Fragment {
            version,
            expires_at,
            token_hash,
            data: body,
        })
    }

    pub fn delete(&mut self, position: &str, token: &[u8; 32]) -> Result<(), String> {
        if !is_valid_position(position) {
            return Err("Invalid position".to_string());
        }

        let mut stored_hash = [0u8; 32];
        let mut head = [0u8; HEADER_SIZE];
        if let Ok(mut f) = fs::File::open(self.path_for(position)) {
            if f.read_exact(&mut head).is_ok() {
                stored_hash.copy_from_slice(&head[9..41]);
                
                let version = head[0];
                let expires = u64::from_be_bytes(head[1..9].try_into().unwrap());
                if version != FRAGMENT_VERSION || expires > now_secs() + MAX_TTL_SECS {
                    let _ = fs::remove_file(self.path_for(position));
                    self.index.remove(position);
                    return Ok(());
                }
            } else {
                let _ = fs::remove_file(self.path_for(position));
                self.index.remove(position);
                return Ok(());
            }
        } else {
            self.index.remove(position);
            return Ok(());
        }

        let mut h = Sha256::new();
        h.update(token);
        let mut incoming_hash = [0u8; 32];
        incoming_hash.copy_from_slice(&h.finalize());

        let mut diff = 0u8;
        for i in 0..32 {
            diff |= stored_hash[i] ^ incoming_hash[i];
        }
        if diff != 0 {
            return Err("Security: refused delete, wrong token".to_string());
        }

        if let Some((_, size)) = self.index.remove(position) {
            self.bytes = self.bytes.saturating_sub(size);
        }
        let _ = fs::remove_file(self.path_for(position));
        Ok(())
    }

    pub fn purge_expired(&mut self) -> usize {
        let now = now_secs();
        let expired: Vec<String> = self
            .index
            .iter()
            .filter(|(_, (exp, _))| *exp < now)
            .map(|(p, _)| p.clone())
            .collect();
        let n = expired.len();
        for p in expired {
            let _ = fs::remove_file(self.path_for(&p));
            self.index.remove(&p);
        }
        n
    }

    pub fn count(&self) -> usize { self.index.len() }
    pub fn bytes(&self) -> u64 { self.bytes }
    pub fn max_bytes(&self) -> u64 { self.max_bytes }
    pub fn set_max_bytes(&mut self, bytes: u64) { self.max_bytes = bytes; }
    pub fn free_bytes(&self) -> u64 { self.max_bytes.saturating_sub(self.bytes) }
}

pub fn dial(host: &str, port: u16, connect_secs: u64) -> Result<TcpStream, String> {
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|_| format!("Cannot resolve '{}'", host))?
        .next()
        .ok_or(format!("Cannot resolve '{}'", host))?;
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(connect_secs))
        .map_err(|_| format!("Could not connect to {}:{}", host, port))?;
    stream.set_nodelay(true).ok();
    stream.set_read_timeout(Some(Duration::from_secs(60))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(60))).ok();
    Ok(stream)
}

pub fn parse_addr(input: &str) -> Result<(String, u16), String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("Empty address".to_string());
    }
    match input.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port.parse().map_err(|_| format!("Bad port in '{}'", input))?;
            if host.is_empty() {
                return Err(format!("Missing host in '{}'", input));
            }
            Ok((host.to_string(), port))
        }
        None => Ok((input.to_string(), DEFAULT_PORT)),
    }
}

pub struct Pool {
    conns: HashMap<String, TcpStream>,
    dead: HashSet<String>,
}

impl Pool {
    pub fn new() -> Self {
        Pool { conns: HashMap::new(), dead: HashSet::new() }
    }

    pub fn request(
        &mut self,
        e: &NodeEntry,
        msg: &Message,
        body: &[u8],
    ) -> Result<(Message, Vec<u8>), String> {
        let key = e.public_key.clone();
        if self.dead.contains(&key) {
            return Err(format!("{}:{} is unreachable", e.ip, e.port));
        }
        let mut last_err = "Request failed".to_string();
        for _ in 0..2 {
            if !self.conns.contains_key(&key) {
                match dial(&e.ip, e.port, 3) {
                    Ok(s) => { self.conns.insert(key.clone(), s); }
                    Err(err) => {
                        self.dead.insert(key);
                        return Err(err);
                    }
                }
            }
            let stream = self.conns.get_mut(&key).unwrap();
            match write_frame(stream, msg, body).and_then(|_| read_frame(stream)) {
                Ok(r) => return Ok(r),
                Err(err) => {
                    self.conns.remove(&key);
                    last_err = err;
                }
            }
        }
        self.dead.insert(key);
        Err(last_err)
    }
}

pub struct Node {
    pub my_hex: String,
    pub port: u16,
    pub dir: PathBuf,
    pub store: Mutex<FragmentStore>,
    pub table: Mutex<NodeTable>,
    pub started: u64,
    pub advertised_addr: Option<String>,
    shutdown: AtomicBool,
}

impl Node {
    pub fn start(my_hex: String, port: u16, dir: PathBuf) -> Result<Arc<Node>, String> {
        let settings = load_settings(&dir);
        let limit = settings.store_limit_bytes.unwrap_or(DEFAULT_MAX_STORE_BYTES);
        Node::start_with_limit(my_hex, port, dir, limit)
    }

    pub fn start_with_limit(my_hex: String, port: u16, dir: PathBuf, max_store_bytes: u64) -> Result<Arc<Node>, String> {
        if !valid_key(&my_hex) {
            return Err("Node key must be 64 hex characters".to_string());
        }
        let listener = TcpListener::bind(("0.0.0.0", port)).map_err(|_| {
            format!("Port {} is already in use.", port)
        })?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();

        fs::create_dir_all(&dir).map_err(|e| format!("Cannot create data folder: {}", e))?;
        let store = FragmentStore::open(dir.join("fragments"), max_store_bytes)?;
        let table = NodeTable::load(&dir.join("nodes.json"), &my_hex);
        let settings = load_settings(&dir);

        let node = Arc::new(Node {
            my_hex, port, dir,
            store: Mutex::new(store),
            table: Mutex::new(table),
            started: now_secs(),
            advertised_addr: settings.advertised_addr,
            shutdown: AtomicBool::new(false),
        });

        let accept = Arc::clone(&node);
        thread::spawn(move || {
            for stream in listener.incoming() {
                if accept.is_shut_down() { break; }
                if let Ok(stream) = stream {
                    let n = Arc::clone(&accept);
                    thread::spawn(move || handle_connection(n, stream));
                }
            }
        });

        let maint = Arc::clone(&node);
        thread::spawn(move || maint.maintenance_loop());

        Ok(node)
    }

    pub fn is_shut_down(&self) -> bool { self.shutdown.load(Ordering::SeqCst) }
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }

    fn maintenance_loop(self: Arc<Self>) {
        let mut elapsed = 0u64;
        loop {
            thread::sleep(Duration::from_secs(1));
            if self.is_shut_down() { return; }
            elapsed += 1;
            if elapsed >= GOSSIP_INTERVAL_SECS {
                elapsed = 0;
                self.store.lock().unwrap().purge_expired();
                self.gossip_once();
                self.save_table();
            }
        }
    }

    pub fn save_table(&self) {
        let table = self.table.lock().unwrap();
        let _ = table.save(&self.dir.join("nodes.json"));
    }

    pub fn saved_bootstrap(&self) -> Option<String> {
        self.table.lock().unwrap().bootstrap.clone()
    }

    pub fn set_bootstrap(&self, b: Option<String>) {
        self.table.lock().unwrap().bootstrap = b;
        self.save_table();
    }

    pub fn set_advertised_addr(&self, addr: Option<String>) {
        let mut settings = load_settings(&self.dir);
        settings.advertised_addr = addr;
        if let Ok(d) = serde_json::to_string_pretty(&settings) {
            let _ = fs::write(self.dir.join("settings.json"), d);
        }
    }

    pub fn known_nodes(&self) -> Vec<NodeEntry> { self.table.lock().unwrap().entries() }
    pub fn ranked(&self, position: &str) -> Vec<Holder> { self.table.lock().unwrap().ranked(position) }

    pub fn announce_to(&self, host: &str, port: u16) -> Result<(), String> {
        let mut stream = dial(host, port, 3)?;
        write_frame(
            &mut stream, 
            &Message::Announce { 
                public_key: self.my_hex.clone(), 
                port: self.port,
                advertised_addr: self.advertised_addr.clone(),
            }, 
            &[]
        )?;
        let (reply, _) = read_frame(&mut stream)?;
        match reply {
            Message::Welcome { public_key, peers, advertised_addr } => {
                if public_key.to_lowercase() == self.my_hex {
                    return Err("That address is this node itself".to_string());
                }
                
                if !self.verify_peer(host, port, &public_key) {
                    return Err("Dial-back verification failed.".to_string());
                }

                let mut table = self.table.lock().unwrap();
                let stored_addr = advertised_addr.unwrap_or_else(|| host.to_string());
                if !table.upsert_direct(NodeEntry::new(public_key, stored_addr, port)) {
                    return Err("The node gave an invalid identity".to_string());
                }
                table.merge_wire_peers(peers, host);
                Ok(())
            }
            Message::Error { message } => Err(message),
            _ => Err("Unexpected reply".to_string()),
        }
    }

    fn verify_peer(&self, host: &str, port: u16, expected_key: &str) -> bool {
        if let Ok(mut stream) = dial(host, port, 3) {
            if write_frame(&mut stream, &Message::Announce { 
                public_key: self.my_hex.clone(), 
                port: self.port,
                advertised_addr: None 
            }, &[]).is_ok() {
                if let Ok((Message::Welcome { public_key, .. }, _)) = read_frame(&mut stream) {
                    return public_key.to_lowercase() == expected_key.to_lowercase();
                }
            }
        }
        false
    }

    pub fn join(&self, bootstrap: &str) -> Result<usize, String> {
        let (host, port) = parse_addr(bootstrap)?;
        self.announce_to(&host, port)?;
        self.set_bootstrap(Some(bootstrap.trim().to_string()));

        let others: Vec<NodeEntry> = self.known_nodes().into_iter()
            .filter(|e| !(e.ip == host && e.port == port))
            .take(MAX_GOSSIP_PER_ROUND).collect();
        for e in others { let _ = self.announce_to(&e.ip, e.port); }
        self.save_table();
        Ok(self.known_nodes().len())
    }

    pub fn gossip_once(&self) {
        let entries: Vec<NodeEntry> = self.known_nodes().into_iter().take(MAX_GOSSIP_PER_ROUND).collect();
        for e in entries {
            if self.announce_to(&e.ip, e.port).is_err() {
                self.table.lock().unwrap().mark_failed(&e.public_key);
            }
        }
    }

    fn handle(&self, msg: Message, body: Vec<u8>, peer_ip: Option<IpAddr>) -> (Message, Vec<u8>) {
        let err = |m: &str| (Message::Error { message: m.to_string() }, Vec::new());
        match msg {
            Message::Announce { public_key, port, advertised_addr } => {
                let ip = match peer_ip {
                    Some(ip) => ip.to_string(),
                    None => return err("Cannot determine your address"),
                };
                let key = public_key.to_lowercase();
                let mut table = self.table.lock().unwrap();
                
                let stored_addr = advertised_addr.unwrap_or(ip);
                
                if !table.upsert_direct(NodeEntry::new(key.clone(), stored_addr, port)) {
                    return err("Invalid announce");
                }
                let peers = table.wire_entries(&key);
                (Message::Welcome { 
                    public_key: self.my_hex.clone(), 
                    peers,
                    advertised_addr: self.advertised_addr.clone(),
                }, Vec::new())
            }
            Message::Put { position, version, expires_at, token_hash } => {
                let now = now_secs();
                if expires_at <= now {
                    return err("Fragment already expired");
                }
                if version != FRAGMENT_VERSION {
                    return err("Unsupported fragment version");
                }
                let frag = Fragment {
                    version,
                    expires_at: expires_at.min(now + MAX_TTL_SECS),
                    token_hash,
                    data: body,
                };
                match self.store.lock().unwrap().put(&position, &frag) {
                    Ok(()) => (Message::Ack, Vec::new()),
                    Err(e) => err(&e),
                }
            }
            Message::Get { position } => match self.store.lock().unwrap().get(&position) {
                Some(f) => (Message::Found { version: f.version, expires_at: f.expires_at }, f.data),
                None => (Message::NotFound, Vec::new()),
            },
            Message::Delete { position, token } => {
                match self.store.lock().unwrap().delete(&position, &token) {
                    Ok(()) => (Message::Ack, Vec::new()),
                    Err(e) => err(&e),
                }
            }
            _ => err("Unexpected message"),
        }
    }

    pub fn put_at(&self, pool: &mut Pool, holder: &Holder, position: &str, frag: &Fragment) -> Result<(), String> {
        match holder {
            Holder::Local => self.store.lock().unwrap().put(position, frag),
            Holder::Remote(e) => {
                let msg = Message::Put {
                    position: position.to_string(),
                    version: frag.version,
                    expires_at: frag.expires_at,
                    token_hash: frag.token_hash,
                };
                match pool.request(e, &msg, &frag.data)? {
                    (Message::Ack, _) => Ok(()),
                    (Message::Error { message }, _) => Err(message),
                    _ => Err("Unexpected reply".to_string()),
                }
            }
        }
    }

    pub fn get_at(&self, pool: &mut Pool, holder: &Holder, position: &str) -> Result<Option<Fragment>, String> {
        match holder {
            Holder::Local => Ok(self.store.lock().unwrap().get(position)),
            Holder::Remote(e) => {
                let msg = Message::Get { position: position.to_string() };
                match pool.request(e, &msg, &[])? {
                    (Message::Found { version, expires_at }, data) => {
                        Ok(Some(Fragment { version, expires_at, token_hash: [0u8; 32], data }))
                    }
                    (Message::NotFound, _) => Ok(None),
                    (Message::Error { message }, _) => Err(message),
                    _ => Err("Unexpected reply".to_string()),
                }
            }
        }
    }

    pub fn delete_at(&self, pool: &mut Pool, holder: &Holder, position: &str, token: &[u8; 32]) -> Result<(), String> {
        match holder {
            Holder::Local => self.store.lock().unwrap().delete(position, token),
            Holder::Remote(e) => {
                match pool.request(e, &Message::Delete { position: position.to_string(), token: *token }, &[])? {
                    (Message::Ack, _) => Ok(()),
                    (Message::Error { message }, _) => Err(message),
                    _ => Err("Unexpected reply".to_string()),
                }
            }
        }
    }

    pub fn store_free_bytes(&self) -> u64 { self.store.lock().unwrap().free_bytes() }
    
    pub fn set_store_limit(&self, bytes: u64) {
        self.store.lock().unwrap().set_max_bytes(bytes);
        let mut settings = load_settings(&self.dir);
        settings.store_limit_bytes = Some(bytes);
        if let Ok(d) = serde_json::to_string_pretty(&settings) {
            let _ = fs::write(self.dir.join("settings.json"), d);
        }
    }

    pub fn store_limit_bytes(&self) -> u64 { self.store.lock().unwrap().max_bytes() }
    
    pub fn status_line(&self) -> (usize, u64, usize, u64) {
        let store = self.store.lock().unwrap();
        let nodes = self.table.lock().unwrap().count();
        (store.count(), store.bytes(), nodes, now_secs() - self.started)
    }
}

fn handle_connection(node: Arc<Node>, mut stream: TcpStream) {
    stream.set_nodelay(true).ok();
    stream.set_read_timeout(Some(Duration::from_secs(300))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(60))).ok();
    let peer_ip = stream.peer_addr().ok().map(|a| a.ip());

    loop {
        let (msg, body) = match read_frame(&mut stream) {
            Ok(v) => v,
            Err(_) => break,
        };
        let (reply, reply_body) = node.handle(msg, body, peer_ip);
        if write_frame(&mut stream, &reply, &reply_body).is_err() {
            break;
        }
    }
}

#[cfg(windows)]
pub fn get_free_disk_space(path: &std::path::Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use std::ffi::OsStr;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetDiskFreeSpaceExW(
            lpDirectoryName: *const u16,
            lpFreeBytesAvailableToCaller: *mut u64,
            lpTotalNumberOfBytes: *mut u64,
            lpTotalNumberOfFreeBytes: *mut u64,
        ) -> i32;
    }

    let path_str = path.to_string_lossy();
    let drive = if path_str.len() >= 2 && path_str.chars().nth(1) == Some(':') {
        format!("{}\\", &path_str[..2])
    } else {
        "C:\\".to_string()
    };

    let wide: Vec<u16> = OsStr::new(&drive).encode_wide().chain(std::iter::once(0)).collect();
    
    let mut free_bytes = 0u64;
    let mut total_bytes = 0u64;
    let mut total_free_bytes = 0u64;

    let result = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free_bytes,
            &mut total_bytes,
            &mut total_free_bytes,
        )
    };

    if result != 0 {
        Some(free_bytes)
    } else {
        None
    }
}

#[cfg(not(windows))]
pub fn get_free_disk_space(_path: &std::path::Path) -> Option<u64> {
    None
}