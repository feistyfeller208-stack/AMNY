# AMNY

**AMNY is an open protocol by which a file on one device becomes inevitable on another — without the file itself, its metadata, its sender, or its recipient ever being exposed in any readable form during transit.**

## The Problem
Every encrypted messaging app (Signal, WhatsApp, Telegram) encrypts the *content* of your messages. But they do not hide the *metadata*. The servers still know who is talking to whom, when they are talking, and how much data is being sent. ISPs and governments can block or trace the connection. 

## The Solution
AMNY is a Layer 0 data transfer protocol. It is not an app; it is the transport layer that apps can be built on.

When you send a file through AMNY:
1. The file is cut into 4MB chunks.
2. Each chunk is split using **Shamir's Secret Sharing** into 5 fragments (any 3 can rebuild the chunk, but 2 reveal mathematically zero information).
3. Each fragment is encrypted using **AES-256-GCM**.
4. The fragments are scattered across a peer-to-peer network. The nodes holding the fragments cannot read them, and they do not know which file they belong to or who sent them.
5. The receiver uses a shared secret to locate and collect the fragments, decrypts them, and reconstructs the file locally.

The file never travels. Only its mathematical shadow does.

## What Does AMNY Do Better?
Compared to existing tools:
* **vs. Signal / WhatsApp:** Hides the connection entirely, not just the content. Nodes cannot see who is talking.
* **vs. Tor / I2P:** Designed specifically for large file transfers and storage, not just web browsing. It uses Shamir's math rather than onion routing.
* **vs. IPFS:** IPFS is public by default. Anyone with the hash can download the file. AMNY is private by default; only the shared secret can locate the fragments.

## Status: Proof of Concept
AMNY is currently in active development. The core cryptographic protocol is fully implemented and passes 28 automated tests, including adversarial security reviews. 

**What works:**
* X25519 key exchange (via libsodium)
* Shamir's Secret Sharing (3-of-5 threshold)
* AES-256-GCM fragment encryption
* Peer-to-peer Kademlia-style fragment routing
* Smart disk limits and junk-file cleanup
* Dial-back verification and hostname support

**What is in progress:**
* Network reachability (NAT traversal, public entry points)
* Performance optimization (parallelizing the Shamir math)
* The ATS token economy (Layer 1)

# Disclaimer
* This is still a prototype. It has not yet undergone a professional third-party cryptographic audit. Do not use it for       life-       critical security yet. We are looking for Rust developers and cryptographers to help review and harden the      codebase.

## How to Build
AMNY is written in Rust.
```bash
cargo build --release
cargo run --release --bin node

