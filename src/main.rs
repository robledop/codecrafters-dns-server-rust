#[allow(unused_imports)]
use std::net::UdpSocket;

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    // println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let message = std::str::from_utf8(&buf[..size]).unwrap();
                println!("Received {} bytes from {}: {}", size, source, message);
                let response: [u8; 12] = [0x04, 0xd2, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
