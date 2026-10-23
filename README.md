# secure-chat

A small encrypted chat between two machines over TCP, written in Rust.

I built this project to learn Rust, network programming and basic applied
cryptography — and to understand how a simple secure communication channel is
actually put together.

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

## Protocol

```
+-----------------+--------------+------------------------------+
| length (u32 BE) | nonce (12 B) | ciphertext + auth tag (16 B) |
+-----------------+--------------+------------------------------+
```

## Getting started

Requires Rust (https://rustup.rs). Works on Linux, macOS and Windows.

```bash
cargo build --release

# Terminal 1
SECURE_CHAT_KEY=secret ./target/release/secure-chat server 127.0.0.1:9000

# Terminal 2
SECURE_CHAT_KEY=secret ./target/release/secure-chat client 127.0.0.1:9000
```

Windows (PowerShell): run `$env:SECURE_CHAT_KEY="secret"` on its own line first.

## Tests

```bash
cargo test
```

- Unit tests: encrypt/decrypt round trip, wrong key, modified message
  (one bit flipped), too-short frame, oversized length field.
- Integration test: sends messages over a real TCP socket.

CI (GitHub Actions) runs `cargo fmt`, `cargo clippy` and `cargo test` on every push.

## Limitations — and what I would do next

This is a learning project and **not** intended for real use. Deliberate simplifications:

- **Key derived from a passphrase with SHA-256.** A real system would use a slow
  KDF (Argon2) or, better, a key exchange (e.g. X25519 / the Noise protocol) so
  the parties don't need a pre-shared secret.
- **No protection against replay or reordering.** An attacker can resend an old
  frame. Fix: a message counter in the nonce / associated data.
- **No forward secrecy.** If the key leaks, past traffic can be decrypted.
- **One client at a time.**

Possible next steps: an X25519 handshake, a message counter against replay,
multiple clients with `tokio`, and a C++ implementation of the same protocol
that can talk to the Rust version.
