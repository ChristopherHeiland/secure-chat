//! secure-chat: encrypted chat between two machines over TCP.
//!
//! Usage:
//!   SECURE_CHAT_KEY=passphrase secure-chat server 0.0.0.0:9000
//!   SECURE_CHAT_KEY=passphrase secure-chat client 127.0.0.1:9000

use secure_chat::SecureChannel;
use std::env;
use std::io::{self, BufRead};
use std::net::{TcpListener, TcpStream};
use std::process;
use std::sync::Arc;
use std::thread;

fn usage() -> ! {
    eprintln!("Usage: SECURE_CHAT_KEY=<passphrase> secure-chat <server|client> <address:port>");
    process::exit(2);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        usage();
    }
    let passphrase = env::var("SECURE_CHAT_KEY").unwrap_or_else(|_| {
        eprintln!("Missing environment variable SECURE_CHAT_KEY");
        process::exit(2);
    });
    let channel = Arc::new(SecureChannel::from_passphrase(&passphrase));

    let stream = match args[1].as_str() {
        "server" => {
            let listener = TcpListener::bind(&args[2]).unwrap_or_else(|e| fail(e));
            println!("Listening on {} – waiting for a client ...", args[2]);
            let (stream, peer) = listener.accept().unwrap_or_else(|e| fail(e));
            println!("Connected: {peer}");
            stream
        }
        "client" => {
            let stream = TcpStream::connect(&args[2]).unwrap_or_else(|e| fail(e));
            println!("Connected to {}", args[2]);
            stream
        }
        _ => usage(),
    };

    if let Err(e) = chat(stream, channel) {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

fn fail(e: io::Error) -> ! {
    eprintln!("Network error: {e}");
    process::exit(1);
}

/// One thread reads from the network and prints, the main thread reads
/// from the keyboard and sends.
fn chat(stream: TcpStream, channel: Arc<SecureChannel>) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = stream.try_clone()?;
    let rx_channel = Arc::clone(&channel);

    thread::spawn(move || {
        loop {
            match rx_channel.recv(&mut reader) {
                Ok(Some(msg)) => println!("< {msg}"),
                Ok(None) => {
                    println!("Peer disconnected.");
                    process::exit(0);
                }
                Err(e) => {
                    eprintln!("Rejected message: {e}");
                    process::exit(1);
                }
            }
        }
    });

    let mut writer = stream;
    for line in io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        channel.send(&mut writer, &line)?;
    }
    Ok(())
}
