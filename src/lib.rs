//! A simple protocol for encrypted messages over TCP.
//!
//! Each message is sent as a frame:
//!
//! ```text
//! +----------------+-------------+---------------------------+
//! | length (u32 BE)| nonce (12 B)| ciphertext + auth tag (16)|
//! +----------------+-------------+---------------------------+
//! ```
//!
//! The length field covers nonce + ciphertext. Messages are encrypted with
//! ChaCha20-Poly1305 (AEAD), so both confidentiality and integrity are
//! protected: a modified or forged frame is rejected.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{self, Read, Write};

/// Nonce length for ChaCha20-Poly1305.
pub const NONCE_LEN: usize = 12;

/// Upper limit for a single frame. Prevents a peer from making us
/// allocate gigabytes by sending a fake length field.
pub const MAX_FRAME_LEN: usize = 64 * 1024;

/// Errors that can occur when sending or receiving messages.
#[derive(Debug)]
pub enum ChatError {
    Io(io::Error),
    FrameTooLarge(usize),
    FrameTooShort(usize),
    /// Decryption failed: wrong key or modified message.
    Decrypt,
    InvalidUtf8,
}

impl fmt::Display for ChatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChatError::Io(e) => write!(f, "I/O error: {e}"),
            ChatError::FrameTooLarge(n) => {
                write!(
                    f,
                    "frame of {n} bytes exceeds the maximum of {MAX_FRAME_LEN}"
                )
            }
            ChatError::FrameTooShort(n) => write!(f, "frame of {n} bytes is too short"),
            ChatError::Decrypt => {
                write!(f, "could not decrypt (wrong key or modified message)")
            }
            ChatError::InvalidUtf8 => write!(f, "message is not valid UTF-8"),
        }
    }
}

impl std::error::Error for ChatError {}

impl From<io::Error> for ChatError {
    fn from(e: io::Error) -> Self {
        ChatError::Io(e)
    }
}

/// Holds the key and encrypts/decrypts frames.
pub struct SecureChannel {
    cipher: ChaCha20Poly1305,
}

impl SecureChannel {
    /// Creates a channel from a shared passphrase.
    ///
    /// NB: hashing the passphrase with SHA-256 is deliberately simple. A real
    /// system would use a slow KDF (e.g. Argon2) or a key exchange protocol.
    pub fn from_passphrase(passphrase: &str) -> Self {
        let digest = Sha256::digest(passphrase.as_bytes());
        let key = Key::from_slice(&digest);
        SecureChannel {
            cipher: ChaCha20Poly1305::new(key),
        }
    }

    /// Encrypts a message and returns the frame (without the length field).
    pub fn seal(&self, plaintext: &str) -> Vec<u8> {
        // A fresh random nonce for every message — reusing a nonce with the
        // same key would break the security.
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .expect("encrypting an in-memory message should not fail");

        let mut frame = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&ciphertext);
        frame
    }

    /// Decrypts a frame (without the length field) back into text.
    pub fn open(&self, frame: &[u8]) -> Result<String, ChatError> {
        // Nonce + at least the 16-byte auth tag.
        if frame.len() < NONCE_LEN + 16 {
            return Err(ChatError::FrameTooShort(frame.len()));
        }
        let (nonce, ciphertext) = frame.split_at(NONCE_LEN);
        let plaintext = self
            .cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| ChatError::Decrypt)?;
        String::from_utf8(plaintext).map_err(|_| ChatError::InvalidUtf8)
    }

    /// Encrypts a message and writes it to a stream (e.g. a TcpStream).
    pub fn send<W: Write>(&self, writer: &mut W, message: &str) -> Result<(), ChatError> {
        let frame = self.seal(message);
        if frame.len() > MAX_FRAME_LEN {
            return Err(ChatError::FrameTooLarge(frame.len()));
        }
        writer.write_all(&(frame.len() as u32).to_be_bytes())?;
        writer.write_all(&frame)?;
        writer.flush()?;
        Ok(())
    }

    /// Reads and decrypts the next message from a stream.
    /// Returns `Ok(None)` when the peer has closed the connection.
    pub fn recv<R: Read>(&self, reader: &mut R) -> Result<Option<String>, ChatError> {
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME_LEN {
            return Err(ChatError::FrameTooLarge(len));
        }
        let mut frame = vec![0u8; len];
        reader.read_exact(&mut frame)?;
        self.open(&frame).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_seal_open() {
        let ch = SecureChannel::from_passphrase("secret");
        let frame = ch.seal("Hello from Kristiansand!");
        assert_eq!(ch.open(&frame).unwrap(), "Hello from Kristiansand!");
    }

    #[test]
    fn same_message_gives_different_ciphertext() {
        let ch = SecureChannel::from_passphrase("secret");
        assert_ne!(ch.seal("same"), ch.seal("same"));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let a = SecureChannel::from_passphrase("correct");
        let b = SecureChannel::from_passphrase("wrong");
        let frame = a.seal("secret message");
        assert!(matches!(b.open(&frame), Err(ChatError::Decrypt)));
    }

    #[test]
    fn tampered_frame_is_rejected() {
        let ch = SecureChannel::from_passphrase("secret");
        let mut frame = ch.seal("transfer 100 NOK");
        let last = frame.len() - 1;
        frame[last] ^= 0x01; // flip a single bit
        assert!(matches!(ch.open(&frame), Err(ChatError::Decrypt)));
    }

    #[test]
    fn short_frame_is_rejected() {
        let ch = SecureChannel::from_passphrase("secret");
        assert!(matches!(
            ch.open(&[0u8; 10]),
            Err(ChatError::FrameTooShort(10))
        ));
    }

    #[test]
    fn send_and_recv_over_stream() {
        let ch = SecureChannel::from_passphrase("secret");
        let mut buf = Vec::new();
        ch.send(&mut buf, "first").unwrap();
        ch.send(&mut buf, "second").unwrap();

        let mut reader = Cursor::new(buf);
        assert_eq!(ch.recv(&mut reader).unwrap().as_deref(), Some("first"));
        assert_eq!(ch.recv(&mut reader).unwrap().as_deref(), Some("second"));
        assert_eq!(ch.recv(&mut reader).unwrap(), None); // stream is empty
    }

    #[test]
    fn oversized_length_field_is_rejected() {
        let ch = SecureChannel::from_passphrase("secret");
        let fake = (u32::MAX).to_be_bytes().to_vec();
        let mut reader = Cursor::new(fake);
        assert!(matches!(
            ch.recv(&mut reader),
            Err(ChatError::FrameTooLarge(_))
        ));
    }
}
