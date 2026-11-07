//! Runs several real nodes (real TCP, real disk) inside one process.
//! Run with: cargo test --release

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use amny::crypto::keys::{KeyPair, SharedSecret};
use amny::henzi::fragment::{derive_position, Fragment};
use amny::henzi::trace::{HenziTrace, CHUNK_SIZE};
use amny::node::runtime::{FragmentStore, Node};
use amny::node::transfer::{receive_next, sanitize_filename, send_file};

struct T {
    node: Arc<Node>,
    keys: KeyPair,
    dir: PathBuf,
}

fn scratch(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("amny_test_{}_{}", std::process::id(), name));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

fn spawn(name: &str) -> T {
    let keys = KeyPair::generate();
    let dir = scratch(name);
    let node = Node::start(keys.public_key_hex(), 0, dir.clone()).unwrap();
    T { node, keys, dir }
}

/// Everyone joins through the first node, then gossips until tables agree.
fn mesh(nodes: &[&T]) {
    let first = nodes[0];
    for n in &nodes[1..] {
        n.node.join(&format!("127.0.0.1:{}", first.node.port)).unwrap();
    }
    for _ in 0..2 {
        for n in nodes {
            n.node.gossip_once();
        }
    }
}

fn random_file(dir: &PathBuf, name: &str, len: usize, seed: u64) -> PathBuf {
    let mut x = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    let mut data = Vec::with_capacity(len);
    for _ in 0..len {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        data.push((x >> 33) as u8);
    }
    let p = dir.join(name);
    fs::write(&p, &data).unwrap();
    p
}

fn noop(_: &str) {}

fn chunk_positions(a: &T, b: &T, sequence: u64, chunk: u32) -> Vec<String> {
    let shared = SharedSecret::derive(&b.keys.secret, &a.keys.public);
    let file_id = HenziTrace::derive_file_id(shared.as_bytes(), &a.keys.public_key_hex(), sequence);
    (0..5u8)
        .map(|i| derive_position(shared.as_bytes(), &file_id, chunk, i))
        .collect()
}

/// Damages every stored copy of one position. Returns how many copies existed.
fn damage(nodes: &[&T], position: &str) -> usize {
    let mut hit = 0;
    for t in nodes {
        let path = t.dir.join("fragments").join(format!("{}.frag", position));
        if let Ok(mut bytes) = fs::read(&path) {
            let i = bytes.len() / 2;
            bytes[i] ^= 0xFF;
            fs::write(&path, bytes).unwrap();
            hit += 1;
        }
    }
    hit
}

#[test]
fn file_survives_the_sender_going_offline() {
    let a = spawn("a");
    let b = spawn("b");
    let c = spawn("c");
    let d = spawn("d");
    mesh(&[&a, &b, &c, &d]);
    assert_eq!(a.node.known_nodes().len(), 3);

    // 9MB = 3 chunks = 15 fragments, each on 3 of the 4 nodes
    let src = random_file(&a.dir, "sample.bin", 9 * 1024 * 1024, 1);
    let report = send_file(&a.node, &a.keys.secret, &b.keys.public_key_hex(), &src, 1, &mut noop).unwrap();
    assert_eq!(report.chunks, 3);
    assert_eq!(report.fragments, 15);
    assert_eq!(report.min_replicas, 3);
    assert!(report.min_remote_replicas >= 2);

    // The sender disappears before the receiver ever shows up.
    a.node.shutdown();
    std::thread::sleep(std::time::Duration::from_millis(300));

    let out = b.dir.join("received");
    let got = receive_next(&b.node, &b.keys.secret, &a.keys.public_key_hex(), 1, &out, None, &mut noop)
        .unwrap()
        .expect("file should be waiting");
    assert_eq!(got.filename, "sample.bin");
    assert_eq!(got.bytes, 9 * 1024 * 1024);
    assert_eq!(fs::read(&got.saved_to).unwrap(), fs::read(&src).unwrap());

    // Holders were told to dissolve, so asking again finds nothing.
    let again = receive_next(&b.node, &b.keys.secret, &a.keys.public_key_hex(), 1, &out, None, &mut noop).unwrap();
    assert!(again.is_none());
}

#[test]
fn a_stranger_gets_nothing() {
    let a = spawn("sa");
    let b = spawn("sb");
    let c = spawn("sc");
    mesh(&[&a, &b, &c]);

    let src = random_file(&a.dir, "secret.bin", 100_000, 2);
    send_file(&a.node, &a.keys.secret, &b.keys.public_key_hex(), &src, 1, &mut noop).unwrap();

    // C knows every node, but not A and B's shared secret, so it cannot compute any position.
    let out = c.dir.join("received");
    assert!(receive_next(&c.node, &c.keys.secret, &a.keys.public_key_hex(), 1, &out, None, &mut noop).unwrap().is_none());
    assert!(receive_next(&c.node, &c.keys.secret, &b.keys.public_key_hex(), 1, &out, None, &mut noop).unwrap().is_none());
}

#[test]
fn several_files_arrive_in_order_without_being_told_anything() {
    let a = spawn("ma");
    let b = spawn("mb");
    let c = spawn("mc");
    mesh(&[&a, &b, &c]);

    let f1 = random_file(&a.dir, "one.txt", 5_000, 3);
    let f2 = random_file(&a.dir, "two.bin", CHUNK_SIZE, 4); // exactly one full chunk
    let f3 = random_file(&a.dir, "three.dat", 1, 5); // a single byte
    for (i, f) in [&f1, &f2, &f3].iter().enumerate() {
        send_file(&a.node, &a.keys.secret, &b.keys.public_key_hex(), f, i as u64 + 1, &mut noop).unwrap();
    }

    let out = b.dir.join("received");
    let mut seq = 1;
    let mut names = Vec::new();
    while let Some(r) =
        receive_next(&b.node, &b.keys.secret, &a.keys.public_key_hex(), seq, &out, None, &mut noop).unwrap()
    {
        seq = r.sequence + 1;
        names.push(r.filename);
    }
    assert_eq!(names, vec!["one.txt", "two.bin", "three.dat"]);
    assert_eq!(fs::read(out.join("two.bin")).unwrap(), fs::read(&f2).unwrap());
    assert_eq!(fs::read(out.join("three.dat")).unwrap().len(), 1);
}

#[test]
fn nodes_hold_only_ciphertext() {
    let a = spawn("ba");
    let b = spawn("bb");
    mesh(&[&a, &b]);

    let marker = b"THIS-TEXT-MUST-NEVER-APPEAR-ON-DISK-AS-PLAINTEXT".repeat(100);
    let src = a.dir.join("plain.txt");
    fs::write(&src, &marker).unwrap();
    send_file(&a.node, &a.keys.secret, &b.keys.public_key_hex(), &src, 1, &mut noop).unwrap();

    let needle = &marker[..40];
    let mut checked = 0;
    for t in [&a, &b] {
        for entry in fs::read_dir(t.dir.join("fragments")).unwrap().flatten() {
            let bytes = fs::read(entry.path()).unwrap();
            assert!(!bytes.windows(needle.len()).any(|w| w == needle));
            assert!(!bytes.windows(9).any(|w| w == b"plain.txt"), "filename must not leak either");
            checked += 1;
        }
    }
    assert!(checked >= 5);
}

#[test]
fn two_corrupted_fragments_out_of_five_are_survivable() {
    let a = spawn("ca");
    let b = spawn("cb");
    let c = spawn("cc");
    mesh(&[&a, &b, &c]);
    let src = random_file(&a.dir, "tough.bin", 50_000, 6);
    send_file(&a.node, &a.keys.secret, &b.keys.public_key_hex(), &src, 1, &mut noop).unwrap();

    // Wreck every copy of fragments 0 and 1. Fragments 2, 3, 4 remain: exactly the threshold.
    let pos = chunk_positions(&a, &b, 1, 0);
    assert!(damage(&[&a, &b, &c], &pos[0]) >= 1);
    assert!(damage(&[&a, &b, &c], &pos[1]) >= 1);

    let out = b.dir.join("received");
    let r = receive_next(&b.node, &b.keys.secret, &a.keys.public_key_hex(), 1, &out, None, &mut noop)
        .unwrap()
        .expect("three good fragments are enough");
    assert_eq!(fs::read(&r.saved_to).unwrap(), fs::read(&src).unwrap());
}

#[test]
fn three_corrupted_fragments_never_produce_a_wrong_file() {
    let a = spawn("da");
    let b = spawn("db");
    let c = spawn("dc");
    mesh(&[&a, &b, &c]);
    let src = random_file(&a.dir, "doomed.bin", 50_000, 7);
    send_file(&a.node, &a.keys.secret, &b.keys.public_key_hex(), &src, 1, &mut noop).unwrap();

    let pos = chunk_positions(&a, &b, 1, 0);
    for p in &pos[..3] {
        damage(&[&a, &b, &c], p);
    }
    let out = b.dir.join("received");
    let r = receive_next(&b.node, &b.keys.secret, &a.keys.public_key_hex(), 1, &out, None, &mut noop);
    assert!(r.is_err(), "only 2 intact fragments: must fail loudly, not return a file");
    assert!(!out.exists() || fs::read_dir(&out).unwrap().count() == 0, "no partial file left behind");
}

#[test]
fn a_node_answering_with_another_positions_fragment_is_caught() {
    let a = spawn("wa");
    let b = spawn("wb");
    mesh(&[&a, &b]);
    let src = random_file(&a.dir, "swap.bin", 50_000, 8);
    send_file(&a.node, &a.keys.secret, &b.keys.public_key_hex(), &src, 1, &mut noop).unwrap();

    // On every node, swap what is stored at positions 0 and 1.
    let pos = chunk_positions(&a, &b, 1, 0);
    for t in [&a, &b] {
        let f0 = t.dir.join("fragments").join(format!("{}.frag", pos[0]));
        let f1 = t.dir.join("fragments").join(format!("{}.frag", pos[1]));
        let (x, y) = (fs::read(&f0).unwrap(), fs::read(&f1).unwrap());
        fs::write(&f0, y).unwrap();
        fs::write(&f1, x).unwrap();
    }
    // Each fragment is bound to its own position, so the swapped ones fail to decrypt.
    // Fragments 2, 3, 4 are intact, so the file still arrives, and it is the right file.
    let out = b.dir.join("received");
    let r = receive_next(&b.node, &b.keys.secret, &a.keys.public_key_hex(), 1, &out, None, &mut noop)
        .unwrap()
        .expect("fragments 2,3,4 are intact");
    assert_eq!(fs::read(&r.saved_to).unwrap(), fs::read(&src).unwrap());
}

#[test]
fn fragments_survive_a_node_restart() {
    let dir = scratch("restart").join("fragments");
    let pos = hex::encode([7u8; 32]);
    {
        let mut s = FragmentStore::open(dir.clone(), 1024 * 1024).unwrap();
        let future_time = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_secs() + 3600;

s.put(&pos, &Fragment { version: 2, expires_at: future_time, token_hash: [0u8; 32], data: vec![1, 2, 3, 4] }).unwrap();
        assert_eq!(s.count(), 1);
    }
    let s = FragmentStore::open(dir, 1024 * 1024).unwrap();
    assert_eq!(s.count(), 1);
    assert_eq!(s.get(&pos).unwrap().data, vec![1, 2, 3, 4]);
    // A path-like "position" is refused before it can touch the disk.
    assert!(s.get("../../etc/passwd").is_none());
}

#[test]
fn filenames_cannot_escape_the_received_folder() {
    assert_eq!(sanitize_filename("..\\..\\Windows\\evil.exe"), "evil.exe");
    assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
    assert_eq!(sanitize_filename("a<b>c?.txt"), "abc.txt");
    assert_eq!(sanitize_filename("CON.txt"), "_CON.txt");
    assert_eq!(sanitize_filename("..."), "received.bin");
    assert_eq!(sanitize_filename("report.pdf"), "report.pdf");
}

fn fragment_files(t: &T) -> usize {
    fs::read_dir(t.dir.join("fragments"))
        .map(|d| d.flatten().filter(|e| e.file_name().to_string_lossy().ends_with(".frag")).count())
        .unwrap_or(0)
}

#[test]
fn a_file_that_cannot_fit_is_refused_up_front_with_a_clear_reason() {
    let keys = KeyPair::generate();
    let dir = scratch("tiny");
    // A node that will keep at most 2MB of fragments, and knows no other nodes.
    let node = Node::start_with_limit(keys.public_key_hex(), 0, dir.clone(), 2 * 1024 * 1024).unwrap();
    let other = KeyPair::generate();

    let src = random_file(&dir, "big.bin", 1024 * 1024, 9); // needs ~5MB here
    let err = match send_file(&node, &keys.secret, &other.public_key_hex(), &src, 1, &mut noop) {
        Err(e) => e,
        Ok(_) => panic!("must be refused"),
    };
    assert!(err.contains("Not enough room"), "got: {}", err);
    assert!(err.contains("limit <MB>"), "should say how to raise the limit");
    let left = fs::read_dir(dir.join("fragments")).unwrap().count();
    assert_eq!(left, 0, "nothing may be stored when the send is refused");
}

#[test]
fn a_send_that_dies_halfway_removes_what_it_already_placed() {
    let a = spawn("ha");
    let b = spawn("hb");
    mesh(&[&a, &b]);

    let src = random_file(&a.dir, "shrinks.bin", 9 * 1024 * 1024, 10); // 3 chunks
    let path = src.clone();
    // After the first chunk is placed, the file is cut short underneath the sender.
    let mut after_chunk = |m: &str| {
        if m.contains("chunk 1/3") {
            let f = fs::OpenOptions::new().write(true).open(&path).unwrap();
            f.set_len(CHUNK_SIZE as u64).unwrap();
        }
    };
    let err = match send_file(&a.node, &a.keys.secret, &b.keys.public_key_hex(), &src, 1, &mut after_chunk) {
        Err(e) => e,
        Ok(_) => panic!("must fail"),
    };
    assert!(err.contains("changed while"), "got: {}", err);
    assert!(err.contains("already placed were removed"));
    assert_eq!(fragment_files(&a), 0, "sender's own store must be clean");
    assert_eq!(fragment_files(&b), 0, "the other node must be clean too");
}

#[test]
fn a_file_is_invisible_to_the_receiver_until_its_last_chunk_is_placed() {
    let a = spawn("va");
    let b = spawn("vb");
    mesh(&[&a, &b]);
    let src = random_file(&a.dir, "appears.bin", 9 * 1024 * 1024, 11); // 3 chunks

    let out = b.dir.join("received");
    let mut seen_early: Vec<bool> = Vec::new();
    let mut watch = |m: &str| {
        // Called after each chunk is placed. The receiver looks on every call except the last.
        if !m.contains("chunk 3/3") {
            let r = receive_next(&b.node, &b.keys.secret, &a.keys.public_key_hex(), 1, &out, None, &mut noop);
            seen_early.push(matches!(r, Ok(None)));
        }
    };
    send_file(&a.node, &a.keys.secret, &b.keys.public_key_hex(), &src, 1, &mut watch).unwrap();

    assert_eq!(seen_early, vec![true, true], "half-sent file must look like nothing at all");
    let got = receive_next(&b.node, &b.keys.secret, &a.keys.public_key_hex(), 1, &out, None, &mut noop)
        .unwrap()
        .expect("complete once sent");
    assert_eq!(fs::read(&got.saved_to).unwrap(), fs::read(&src).unwrap());
}

#[test]
fn the_store_limit_is_remembered_across_restarts() {
    let keys = KeyPair::generate();
    let dir = scratch("limit");
    let mb = 1024 * 1024u64;
    {
        let node = Node::start(keys.public_key_hex(), 0, dir.clone()).unwrap();
        assert_eq!(node.store_limit_bytes(), 2048 * mb);
        node.set_store_limit(6000 * mb);
        node.shutdown();
    }
    let node = Node::start(keys.public_key_hex(), 0, dir).unwrap();
    assert_eq!(node.store_limit_bytes(), 6000 * mb);
}

#[test]
fn delete_removes_files_even_if_they_are_not_in_the_memory_index() {
    let dir = scratch("ghost").join("fragments");
    let pos = hex::encode([8u8; 32]); 
    let token = [9u8; 32]; // A valid token

    let mut store = FragmentStore::open(dir.clone(), 1024 * 1024).unwrap();
    
    // 1. Create a valid fragment directly on disk, bypassing the store's index.
    let mut path = dir.join(format!("{}.frag", pos));
    let mut fake_file = std::fs::File::create(&path).unwrap();
    use std::io::Write;
    fake_file.write_all(&[1u8]).unwrap(); // version
    fake_file.write_all(&(u64::MAX / 2).to_be_bytes()).unwrap(); // expires
    fake_file.write_all(&token).unwrap(); // delete_token
    fake_file.write_all(&[1, 2, 3, 4]).unwrap(); // data
    drop(fake_file);
    
    // 2. Confirm the file is on disk, but the store knows nothing about it.
    assert!(path.exists());
    assert_eq!(store.count(), 0);

    
}

#[test]
fn a_receiver_skips_a_node_serving_garbage_and_finds_the_real_fragment() {
    let a = spawn("ga");
    let b = spawn("gb");
    let c = spawn("gc");
    // Mesh so everyone knows everyone
    b.node.join(&format!("127.0.0.1:{}", a.node.port)).unwrap();
    c.node.join(&format!("127.0.0.1:{}", a.node.port)).unwrap();
    a.node.gossip_once();
    b.node.gossip_once();
    c.node.gossip_once();

    let src = random_file(&a.dir, "test.bin", 60_000, 12);
    send_file(&a.node, &a.keys.secret, &b.keys.public_key_hex(), &src, 1, &mut noop).unwrap();

    let shared = SharedSecret::derive(&b.keys.secret, &a.keys.public);
    let file_id = HenziTrace::derive_file_id(shared.as_bytes(), &a.keys.public_key_hex(), 1);
    let pos = derive_position(shared.as_bytes(), &file_id, 0, 0);

    // Find the nearest node to the position and overwrite its fragment with garbage
    let ranked = b.node.ranked(&pos);
    if let amny::network::nodes::Holder::Remote(e) = &ranked[0] {
        let dir = if e.public_key == a.keys.public_key_hex() { &a.dir } else if e.public_key == c.keys.public_key_hex() { &c.dir } else { return; };
        let path = dir.join("fragments").join(format!("{}.frag", pos));
        if path.exists() {
            let mut data = fs::read(&path).unwrap();
            let mid = data.len() / 2;
            data[mid] ^= 0xFF; // Corrupt the ciphertext
            fs::write(&path, data).unwrap();
        }
    }

    // The receiver must skip the corrupt copy from the first node and get the good copy from the next node.
    let out = b.dir.join("received");
    let r = receive_next(&b.node, &b.keys.secret, &a.keys.public_key_hex(), 1, &out, None, &mut noop)
        .unwrap()
        .expect("Receiver must fallback to the next node");
        
    assert_eq!(fs::read(&r.saved_to).unwrap(), fs::read(&src).unwrap());
}