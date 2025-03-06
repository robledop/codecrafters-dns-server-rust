mod dns_header;

use crate::dns_header::DnsHeader;
use std::io::LineWriter;
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
                // let request: DnsHeader = DnsHeader::parse(buf[..12] as [u8; 12]);
                let mut header: DnsHeader = DnsHeader::new();
                header.id = 1234;
                header.qr = true;

                println!("Received {} bytes from {}", size, source);
                let response = header.to_bytes();
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
