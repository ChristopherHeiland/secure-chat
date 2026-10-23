//! Integration test: sends encrypted messages over a real TCP socket.

use secure_chat::SecureChannel;
use std::net::{TcpListener, TcpStream};
use std::thread;

#[test]
fn messages_survive_a_real_tcp_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap(); // OS picks a free port
    let addr = listener.local_addr().unwrap();

    let server = thread::spawn(move || {
        let ch = SecureChannel::from_passphrase("shared-key");
        let (mut stream, _) = listener.accept().unwrap();
        let msg = ch.recv(&mut stream).unwrap().unwrap();
        ch.send(&mut stream, &format!("echo: {msg}")).unwrap();
    });

    let ch = SecureChannel::from_passphrase("shared-key");
    let mut client = TcpStream::connect(addr).unwrap();
    ch.send(&mut client, "ping").unwrap();
    let reply = ch.recv(&mut client).unwrap().unwrap();

    assert_eq!(reply, "echo: ping");
    server.join().unwrap();
}
