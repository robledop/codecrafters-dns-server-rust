mod dns_header;

use crate::dns_header::{DnsHeader, DnsPacket, DnsQuestion};
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
                let mut response_packet = DnsPacket::new();
                response_packet.header.id = request.id;
                response_packet.header.qr = true; // It's a response

                response_packet.questions.push(DnsQuestion::new(
                    "codecrafters.io".to_string(),
                    1,
                    1,
                ));

                response_packet.header.qdcount = response_packet.questions.len() as u16;

                println!("Received {} bytes from {}", size, source);
                let response = response_packet.to_bytes();

                println!("Sending response: {:?}", response_packet);
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
