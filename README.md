# secure-chat

A small encrypted chat between two machines over TCP, written in Rust.

I built this project to learn Rust, network programming and basic applied
cryptography.

```
$ SECURE_CHAT_KEY=secret secure-chat server 0.0.0.0:9000
Listening on 0.0.0.0:9000 – waiting for a client ...
Connected: 192.168.1.20:50454
< hello server
```

## Features

- **Authenticated encryption (AEAD):** Every message is encrypted with
  ChaCha20-Poly1305. A message that was modified in transit, or sent with the
  wrong key, is rejected instead of displayed.
- **Fresh nonce per message:** The same text sent twice produces different ciphertext.
- **Custom framing protocol over TCP:** TCP is a byte stream with no message
  boundaries, so every message is prefixed with a length field.
- **Protection against fake length fields:** Frames over 64 KiB are rejected
  before any memory is allocated.
- **Two-way chat:** one thread reads from the network, the main thread reads
  from the keyboard.


## Getting started

Requires Rust (https://rustup.rs). Works on Linux, macOS and Windows.

```bash
cargo build --release

# Terminal 1
$env:SECURE_CHAT_KEY="secret"
cargo run -- server 127.0.0.1:9000

# Terminal 2
$env:SECURE_CHAT_KEY="secret"
cargo run -- client 127.0.0.1:9000

```


## Limitations — and what I would do next
- **Key derived from a passphrase with SHA-256.** A real system would use a slow
  KDF (Argon2) or, better, a key exchange (e.g. X25519 / the Noise protocol) so
  the parties don't need a pre-shared secret.
- **No protection against replay or reordering.** An attacker can resend an old
  frame. Fix: a message counter in the nonce / associated data.
- **No forward secrecy.** If the key leaks, past traffic can be decrypted.
- **One client at a time.**

