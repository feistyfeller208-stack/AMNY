use std::env;
use std::fs;
use std::io::Write;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use amny::crypto::contacts::ContactBook;
use amny::node::runtime::{Node, DEFAULT_PORT};
use amny::node::transfer::{receive_next, send_file, Sequences};

// Hides the input (used for passwords)
fn prompt_raw(label: &str) -> Result<String, String> {
    rpassword::prompt_password(label).map_err(|e| format!("Failed to read password: {}", e))
}

// Everything else: visible input, strips quotes and invisible characters
fn prompt(label: &str) -> Result<String, String> {
    print!("{}", label);
    std::io::stdout().flush().ok();

    let mut s = String::new();
    std::io::stdin()
        .read_line(&mut s)
        .map_err(|_| "Failed to read input".to_string())?;
        
    let raw = s.trim_end_matches(&['\r', '\n'][..]).to_string();
    let cleaned: String = raw
        .chars()
        .filter(|c| {
            !matches!(*c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{feff}' | '"')
        })
        .collect();
    Ok(cleaned.trim().to_string())
}

fn local_ip() -> Option<String> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?; // sends nothing, only picks a route
    Some(sock.local_addr().ok()?.ip().to_string())
}

fn short(key: &str) -> &str {
    key.get(..12).unwrap_or(key)
}

fn run() -> Result<(), String> {
    println!("----------------------------------------");
    println!("AMNY/1 node");
    println!("----------------------------------------\n");

    let args: Vec<String> = env::args().collect();

    let port: u16 = match args.get(1) {
        Some(p) => p.parse().map_err(|_| "Port must be a number".to_string())?,
        None => {
            let s = prompt(&format!("Port [{}]: ", DEFAULT_PORT))?;
            if s.is_empty() {
                DEFAULT_PORT
            } else {
                s.parse().map_err(|_| "Port must be a number".to_string())?
            }
        }
    };

    // Each port gets its own folder, so several nodes can run on one machine.
    let dir = PathBuf::from("amny_data").join(port.to_string());
    fs::create_dir_all(&dir).map_err(|e| format!("Cannot create {}: {}", dir.display(), e))?;
    let key_path = dir.join("node.key");
    let contacts_path = dir.join("contacts.json");
    let sequences_path = dir.join("sequences.json");
    let out_dir = dir.join("received");

    let is_new = !key_path.exists();
    let password_prompt = if is_new {
        "Enter new keystore password: "
    } else {
        "Keystore password: "
    };
    
    let password = prompt_raw(password_prompt)?;
    
    // N5 Fix: Confirm password on creation
    if is_new {
        let confirm = prompt_raw("Confirm password: ")?;
        if password != confirm {
            return Err("Passwords do not match. Aborting.".to_string());
        }
    }

    let keys = amny::crypto::keystore::load_or_generate(
        key_path.to_str().ok_or("Bad path")?,
        &password,
    )?;
    let my_hex = keys.public_key_hex();
    println!("\nYour public key:\n{}\n", my_hex);

    let node = Node::start(my_hex.clone(), port, dir.clone())?;

    // Joining: one address of any running node is enough.
    let saved = node.saved_bootstrap();
    let bootstrap = match args.get(2) {
        Some(b) => b.clone(),
        None => {
            let label = match &saved {
                Some(s) => format!("Join through (host:port) [{}] (Enter to keep, - for none): ", s),
                None => "Join through (host:port), or Enter if this is the first node: ".to_string(),
            };
            let s = prompt(&label)?;
            if s.is_empty() {
                saved.clone().unwrap_or_default()
            } else if s == "-" {
                node.set_bootstrap(None);
                String::new()
            } else {
                s
            }
        }
    };

    if bootstrap.is_empty() {
        let n = Arc::clone(&node);
        thread::spawn(move || n.gossip_once()); // reconnect to nodes remembered from last time
    } else {
        match node.join(&bootstrap) {
            Ok(n) => println!("Joined through {}. Known nodes: {}", bootstrap, n),
            Err(e) => println!("Could not join through {}: {}", bootstrap, e),
        }
    }
    if let Some(ip) = local_ip() {
        println!("Other nodes can join through: {}:{}", ip, node.port);
    }

    let mut contacts = ContactBook::load(contacts_path.to_str().ok_or("Bad path")?);
    let mut sequences = Sequences::load(&sequences_path);

    println!("\nCommands:");
    println!("  me                          show your public key");
    println!("  add <name> <public_key>     save a contact");
    println!("  contacts                    list contacts");
    println!("  send <contact> <file>       send a file");
    println!("  receive <contact> [name]    collect files a contact sent you");
    println!("  limit [MB]                  show or set how much this node stores");
    println!("  nodes | status | exit\n");

    loop {
        let input = prompt("> ")?;
        if input.is_empty() {
            continue;
        }
        let parts: Vec<&str> = input.splitn(3, ' ').collect();

        match parts[0] {
            "me" => println!("{}", my_hex),

            "add" => {
                if parts.len() < 3 {
                    println!("Usage: add <name> <public_key>");
                    continue;
                }
                let key = parts[2].trim().to_lowercase();
                if key.len() != 64 || !key.chars().all(|c| c.is_ascii_hexdigit()) {
                    println!("A public key is 64 hex characters. Check what you pasted.");
                    continue;
                }
                if key == my_hex {
                    println!("That is your own key.");
                    continue;
                }
                                if let Some(existing) = contacts.get(parts[1]) {
                    if existing.public_key_hex != key {
                        println!(
                            "WARNING: The key for '{}' is changing. If you did not reset their node, this could be a man-in-the-middle attack.",
                            parts[1]
                        );
                    }
                }

                contacts.add(parts[1].to_string(), key);
                match contacts.save(contacts_path.to_str().ok_or("Bad path")?) {
                    Ok(_) => println!("Saved contact {}", parts[1]),
                    Err(e) => println!("Error: {}", e),
                }
            }

            "contacts" => {
                if contacts.is_empty() {
                    println!("No contacts yet. Use: add <name> <public_key>");
                }
                for c in contacts.list() {
                    println!("  {}  {}...", c.name, short(&c.public_key_hex));
                }
            }

            "send" => {
                if parts.len() < 3 {
                    println!("Usage: send <contact> <file>");
                    continue;
                }
                let contact = match contacts.get(parts[1]) {
                    Some(c) => c.clone(),
                    None => {
                        println!("No contact named '{}'", parts[1]);
                        continue;
                    }
                };
                let sequence = sequences.get(&contact.public_key_hex).sent + 1;
                println!("Henzifying...");
                let mut progress = |m: &str| println!("{}", m);
                match send_file(
                    &node,
                    &keys.secret,
                    &contact.public_key_hex,
                    Path::new(parts[2]),
                    sequence,
                    &mut progress,
                ) {
                    Ok(r) => {
                        sequences.set_sent(&contact.public_key_hex, sequence);
                        sequences.save(&sequences_path);
                        println!(
                            "Sent {} bytes as {} fragments. Every fragment has at least {} copies.",
                            r.bytes, r.fragments, r.min_replicas
                        );
                        if r.min_remote_replicas == 0 {
                            println!("Warning: some fragments exist only on this machine.");
                            println!("Keep this node running until {} collects the file.", contact.name);
                        } else {
                            println!("{} can collect it even if this node goes offline.", contact.name);
                        }
                    }
                    Err(e) => println!("Error: {}", e),
                }
            }

            "receive" => {
                if parts.len() < 2 {
                    println!("Usage: receive <contact> [save_as]");
                    continue;
                }
                let contact = match contacts.get(parts[1]) {
                    Some(c) => c.clone(),
                    None => {
                        println!("No contact named '{}'", parts[1]);
                        continue;
                    }
                };
                let mut name_override = parts.get(2).map(|s| s.to_string());
                let mut count = 0;
                loop {
                    let start = sequences.get(&contact.public_key_hex).received + 1;
                    let mut progress = |m: &str| println!("{}", m);
                    match receive_next(
                        &node,
                        &keys.secret,
                        &contact.public_key_hex,
                        start,
                        &out_dir,
                        name_override.as_deref(),
                        &mut progress,
                    ) {
                        Ok(Some(r)) => {
                            sequences.set_received(&contact.public_key_hex, r.sequence);
                            sequences.save(&sequences_path);
                            println!("Saved {} ({} bytes) to {}", r.filename, r.bytes, r.saved_to.display());
                            name_override = None;
                            count += 1;
                        }
                        Ok(None) => {
                            if count == 0 {
                                println!(
                                    "Nothing from {} yet. Ask them to send, and check that nodes holding the fragments are online.",
                                    contact.name
                                );
                            }
                            break;
                        }
                        Err(e) => {
                            println!("Error: {}", e);
                            break;
                        }
                    }
                }
            }

            "nodes" => {
                let nodes = node.known_nodes();
                if nodes.is_empty() {
                    println!("No other nodes known. Fragments you send stay on this machine.");
                }
                for e in nodes {
                    println!(
                        "  {}...  {}:{}{}",
                        short(&e.public_key),
                        e.ip,
                        e.port,
                        if e.failures > 0 { "  (not responding)" } else { "" }
                    );
                }
            }

            "status" => {
                let (frags, bytes, nodes, up) = node.status_line();
                println!("Node      {}...", short(&my_hex));
                println!("Port      {}", node.port);
                println!(
                    "Holding   {} fragments, {} MB of {} MB limit",
                    frags,
                    bytes / (1024 * 1024),
                    node.store_limit_bytes() / (1024 * 1024)
                );
                println!("Known     {} other nodes", nodes);
                println!("Uptime    {}h {}m", up / 3600, (up % 3600) / 60);
            }

            "limit" => match parts.get(1).map(|v| v.trim().parse::<u64>()) {
                None => println!(
                    "This node keeps up to {} MB of fragments. Change it with: limit <MB>",
                    node.store_limit_bytes() / (1024 * 1024)
                ),
                Some(Ok(mb)) if mb >= 64 => {
                    let requested_bytes = mb * 1024 * 1024;
                    if let Some(free_bytes) = amny::node::runtime::get_free_disk_space(&node.dir) {
                        // N3 Fix: Compare the NEW data against free space, not the total limit.
                        let additional_needed = requested_bytes.saturating_sub(node.store_limit_bytes());
                        let safe_max = (free_bytes as f64 * 0.9) as u64;
                        
                        if additional_needed > safe_max {
                            println!(
                                "Error: You requested {} MB, but this drive only has {} MB free.",
                                mb,
                                free_bytes / (1024 * 1024)
                            );
                            println!("To protect your system, AMNY limits storage to 90% of your free space.");
                            continue;
                        }
                    } else {
                        println!("Warning: Could not read disk space. Setting limit anyway.");
                    }

                    node.set_store_limit(requested_bytes);
                    println!("Limit set to {} MB. It is remembered for next time.", mb);
                }
                _ => println!("Give a whole number of MB, at least 64. Example: limit 6000"),
            },

            "exit" => {
                node.save_table();
                println!("Shutting down.");
                node.shutdown();
                break;
            }

            "advertise" => match parts.get(1) {
                None => {
                    if let Some(addr) = &node.advertised_addr {
                        println!("This node is advertising itself as: {}", addr);
                    } else {
                        println!("This node is not advertising an address.");
                    }
                    println!("Change it with: advertise <host:port>  (or 'advertise -' to clear)");
                }
                Some(&"-") => {
                    node.set_advertised_addr(None);
                    println!("Advertised address cleared.");
                }
                Some(&addr) => {
                    node.set_advertised_addr(Some(addr.to_string()));
                    println!("Advertised address set to: {}", addr);
                }
            },

            _ => println!("Unknown command."),
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("\nError: {}", e);
        eprintln!("\nPress Enter to exit.");
        let mut p = String::new();
        std::io::stdin().read_line(&mut p).ok();
        std::process::exit(1);
    }
}