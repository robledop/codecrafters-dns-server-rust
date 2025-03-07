mod dns;

#[allow(unused_imports)]
use crate::dns::{DnsPacket, DnsQuestion, DnsRecord, Qclass, Qtype};
use std::env;
use std::net::{SocketAddr, UdpSocket};

const HEADER_SIZE: usize = 12;

fn main() {
    env::set_var("RUST_BACKTRACE", "1");
    let args: Vec<String> = env::args().collect();
    dbg!(&args);

    let mut request_queue: Vec<(u16, SocketAddr, DnsPacket)> = Vec::new();
    let mut response_queue: Vec<(u16, SocketAddr, DnsPacket)> = Vec::new();

    let mut resolver_address: String = "".to_string();
    let mut i = 0;
    for arg in args.iter() {
        if arg == "--resolver" && args.len() > i + 1 {
            resolver_address = args[i + 1].clone();
        }

        i += 1;
    }

    let udp_socket = UdpSocket::bind("0.0.0.0:2053").expect("Failed to bind to address");
    let mut buf = [0; 20480];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((_, source)) => {
                let request: DnsPacket = DnsPacket::parse(buf.to_vec().into_boxed_slice());

                // It's a response
                if request.header.qr {
                    println!("Received response from {:?}: {:?}", source, request.clone());

                    let response = request.clone();

                    let request_index = request_queue
                        .iter()
                        .position(|x| x.0 == response.header.id)
                        .unwrap();

                    let (_, client_address, original_request) =
                        request_queue.get(request_index).unwrap();

                    if original_request.header.qdcount > 1 {
                        // The request has more than one question. We need to break it into
                        // multiple queries and then combine the responses from the forwarder
                        // into a single response back to the client

                        let response_index = response_queue
                            .iter()
                            .position(|x| x.0 == original_request.header.id);

                        // If the index is some, that means we already received at least one response
                        // from the forwarder, and now we need to combine the responses
                        if response_index.is_some() {
                            let (_, address, existing_response) =
                                response_queue.get(response_index.unwrap()).unwrap();
                            let mut existing_response = existing_response.clone();
                            existing_response.header.qdcount += 1;
                            existing_response.header.ancount += 1;

                            existing_response
                                .questions
                                .extend(response.questions.clone());
                            existing_response.answers.extend(response.answers.clone());

                            if existing_response.header.ancount == original_request.header.qdcount {
                                println!(
                                    "Sending COMBINED response to {:?}: {:?}",
                                    address, existing_response
                                );

                                udp_socket
                                    .send_to(&existing_response.to_bytes(), address)
                                    .expect("Failed to send response");

                                response_queue.remove(response_index.unwrap());
                                request_queue.remove(request_index);
                            }
                        } else {
                            response_queue.push((
                                original_request.header.id,
                                *client_address,
                                response.clone(),
                            ));
                        }
                    } else {
                        println!("Sending response to {:?}: {:?}", client_address, response);

                        udp_socket
                            .send_to(&response.to_bytes(), client_address)
                            .expect("Failed to send response");

                        let response_index = response_queue
                            .iter()
                            .position(|x| x.0 == response.header.id);
                        if response_index.is_some() {
                            response_queue.remove(response_index.unwrap());
                        }

                        request_queue.remove(request_index);
                    }
                } else {
                    println!("Received query from {:?}: {:?}", source, request.clone());

                    request_queue.push((request.header.id, source, request.clone()));

                    if request.header.qdcount > 1 {
                        for question in request.questions.iter() {
                            let mut forwarded_request = request.clone();
                            forwarded_request.header.qdcount = 1;
                            forwarded_request.questions.clear();
                            forwarded_request.questions.push(question.clone());

                            println!(
                                "Forwarding request to {}: {:?}",
                                resolver_address.clone(),
                                forwarded_request.clone()
                            );

                            forwarded_request.header.qr = false;

                            udp_socket
                                .send_to(&forwarded_request.to_bytes(), resolver_address.clone())
                                .expect("Failed to forward request");
                        }
                    } else {
                        println!(
                            "Forwarding request to {}: {:?}",
                            resolver_address.clone(),
                            request.clone()
                        );

                        udp_socket
                            .send_to(&request.to_bytes(), resolver_address.clone())
                            .expect("Failed to forward request");
                    }
                }
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
