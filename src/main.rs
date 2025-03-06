mod dns_header;

use crate::dns_header::DnsHeader;
use std::io::LineWriter;
#[allow(unused_imports)]
use std::net::UdpSocket;

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let request: DnsHeader = DnsHeader::parse(buf.to_vec().into_boxed_slice());
                println!("Received request: {:?}", request);
                let mut header: DnsHeader = DnsHeader::new();
                header.id = request.id;
                header.qr = request.qr;

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
