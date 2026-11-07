use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use amny::crypto::keys::{KeyPair, SharedSecret};
use amny::henzi::fragment::{derive_position, now_secs, derive_delete_token};
use amny::henzi::trace::HenziTrace;
use amny::network::protocol::{read_frame, write_frame, Message};
use amny::node::runtime::{dial, FragmentStore, Node};
use amny::node::transfer::{receive_next, send_file};

struct T {
    node: Arc<Node>,
    keys: KeyPair,
    dir: PathBuf,
}

fn spawn(name: &str) -> T {
    let keys = KeyPair::generate();
    let dir = std::env::temp_dir().join(format!("amny_review_{}_{}", std::process::id(), name));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let node = Node::start(keys.public_key_hex(), 0, dir.clone()).unwrap();
    T { node, keys, dir }
}

fn noop(_: &str) {}

fn frag_path(t: &T, pos: &str) -> PathBuf {
    t.dir.join("fragments").join(format!("{}.frag", pos))
}

fn count_files(t: &T) -> usize {
    fs::read_dir(t.dir.join("fragments")).unwrap().count()
}

fn ask(port: u16, msg: Message, body: &[u8]) -> Message {
    let mut s = dial("127.0.0.1", port, 3).unwrap();
    write_frame(&mut s, &msg, body).unwrap();
    read_frame(&mut s).map(|r| r.0).unwrap_or(Message::Error { message: "no reply".into() })
}

fn setup(name: &str) -> (T, T, Vec<String>, SharedSecret) {
    let a = spawn(&format!("{}a", name));
    let b = spawn(&format!("{}b", name));
    b.node.join(&format!("127.0.0.1:{}", a.node.port)).unwrap();
    a.node.gossip_once();
    let src = a.dir.join("f.bin");
    fs::write(&src, vec![42u8; 60_000]).unwrap();
    send_file(&a.node, &a.keys.secret, &b.keys.public_key_hex(), &src, 1, &mut noop).unwrap();
    let shared = SharedSecret::derive(&b.keys.secret, &a.keys.public);
    let fid = HenziTrace::derive_file_id(shared.as_bytes(), &a.keys.public_key_hex(), 1);
    let pos = (0..5u8).map(|i| derive_position(shared.as_bytes(), &fid, 0, i)).collect();
    (a, b, pos, shared)
}

#[test]
fn wrong_token_leaves_the_fragment() {
    let (_a, b, pos, _shared) = setup("w");
    ask(b.node.port, Message::Delete { position: pos[0].clone(), token: [0u8; 32] }, &[]);
    assert!(frag_path(&b, &pos[0]).exists());
}

#[test]
fn an_occupied_position_cannot_be_overwritten() {
    let (_a, b, pos, _shared) = setup("o");
    let before = fs::read(frag_path(&b, &pos[0])).unwrap();
    let reply = ask(
        b.node.port,
        Message::Put { position: pos[0].clone(), version: 1, expires_at: now_secs() + 1000, token_hash: [9u8; 32] },
        &[1u8; 100],
    );
    assert!(matches!(reply, Message::Error { .. }), "overwrite must be refused, got {:?}", reply);
    assert_eq!(fs::read(frag_path(&b, &pos[0])).unwrap(), before, "stored fragment must be unchanged");
}

#[test]
fn the_owner_can_still_delete_after_someone_tried_to_overwrite() {
    let (_a, b, pos, shared) = setup("d");
    let owner_token = derive_delete_token(shared.as_bytes(), &pos[0]);
    
    ask(
        b.node.port,
        Message::Put { position: pos[0].clone(), version: 1, expires_at: now_secs() + 1000, token_hash: [9u8; 32] },
        &[1u8; 100],
    );
    ask(b.node.port, Message::Delete { position: pos[0].clone(), token: owner_token }, &[]);
    assert!(!frag_path(&b, &pos[0]).exists(), "the real owner's token must still work");
}

#[test]
fn a_retried_identical_put_is_accepted() {
    let (_a, b, pos, _shared) = setup("r");
    let file = fs::read(frag_path(&b, &pos[0])).unwrap();
    let reply = ask(
        b.node.port,
        Message::Put { position: pos[0].clone(), version: file[0], expires_at: now_secs() + 1000, token_hash: file[9..41].try_into().unwrap() },
        &file[41..],
    );
    assert!(matches!(reply, Message::Ack), "a sender retrying after a dropped connection must not be refused");
}

#[test]
fn junk_replacing_a_fragment_is_cleaned_up_by_receive() {
    for len in [200usize, 30] {
        let (a, b, pos, _shared) = setup(&format!("j{}", len));
        for t in [&a, &b] {
            fs::write(frag_path(t, &pos[0]), vec![7u8; len]).unwrap();
        }
        let out = b.dir.join("received");
        let r = receive_next(&b.node, &b.keys.secret, &a.keys.public_key_hex(), 1, &out, None, &mut noop);
        assert!(matches!(r, Ok(Some(_))), "the file still arrives from the other four fragments");
        assert_eq!(count_files(&a) + count_files(&b), 0, "{}-byte junk was left behind", len);
    }
}

#[test]
fn junk_files_are_removed_when_a_node_starts() {
    let dir = std::env::temp_dir().join(format!("amny_review_junk_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    for (i, len) in [200usize, 30].iter().enumerate() {
        let name = format!("{}.frag", hex::encode([i as u8 + 1; 32]));
        fs::write(dir.join(name), vec![0xFFu8; *len]).unwrap();
    }
    let mut s = FragmentStore::open(dir.clone(), 1 << 30).unwrap();
    s.purge_expired();
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 0, "files that are not valid fragments must not live forever");
}

#[test]
fn what_a_node_stores_is_not_enough_to_delete_other_nodes_copies() {
    let (a, b, pos, _shared) = setup("s");
    // B tries every 32-byte window of the header it stores as a delete token, against A.
    for p in &pos {
        let head = fs::read(frag_path(&b, p)).unwrap();
        for start in 0..=(head.len().min(64) - 32) {
            let token: [u8; 32] = head[start..start + 32].try_into().unwrap();
            ask(a.node.port, Message::Delete { position: p.clone(), token }, &[]);
        }
    }
    let left = pos.iter().filter(|p| frag_path(&a, p).exists()).count();
    assert_eq!(left, 5, "a holder must not be able to wipe another node's copies from what it stores");
}

#[test]
fn a_refused_delete_is_reported_as_an_error() {
    let (_a, b, pos, _shared) = setup("e");
    let reply = ask(b.node.port, Message::Delete { position: pos[0].clone(), token: [0u8; 32] }, &[]);
    assert!(matches!(reply, Message::Error { .. }), "got {:?}", reply);
}