mod dns;

use crate::dns::{DnsPacket, DnsQuestion, DnsRecord, Qclass, Qtype};
#[allow(unused_imports)]
use std::net::UdpSocket;

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let request: DnsPacket = DnsPacket::parse(buf.to_vec().into_boxed_slice());
                println!("Received request: {:?}", request);
                let mut response_packet = DnsPacket::new();
                response_packet.header.id = request.header.id;
                response_packet.header.qr = true; // It's a response
                response_packet.header.opcode = request.header.opcode;
                response_packet.header.rd = request.header.rd;

                if request.header.opcode != 0 {
                    response_packet.header.rcode = 4; // not implemented
                }

                response_packet.questions = request.questions;

                response_packet.header.qdcount = response_packet.questions.len() as u16;

                let rdata: [u8; 4] = [8, 8, 8, 8];

                for question in response_packet.questions.iter() {
                    response_packet.answers.push(DnsRecord::new(
                        question.qname.clone(),
                        question.qtype,
                        question.qclass,
                        60,
                        rdata.len() as u16,
                        rdata.to_vec(),
                    ));
                }

                response_packet.header.ancount = response_packet.answers.len() as u16;

                println!("Received {} bytes from {}", size, source);

                println!("Sending response: {:?}", response_packet);
                udp_socket
                    .send_to(&response_packet.to_bytes(), source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
