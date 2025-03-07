mod dns;

#[allow(unused_imports)]
use crate::dns::{DnsPacket, DnsQuestion, DnsRecord, Qclass, Qtype};
use std::env;
use std::net::{SocketAddr, UdpSocket};

fn main() {
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

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((_, source)) => {
                let request: DnsPacket = DnsPacket::parse(buf.to_vec().into_boxed_slice());
                request_queue.push((request.header.id, source, request.clone()));

                if request.header.qr {
                    if request.answers.len() > 0 {
                        println!("Received response from {:?}: {:?}", source, request.clone());

                        let mut response = request.clone();
                        // response.header.qr = true;

                        let index = request_queue
                            .iter()
                            .position(|x| x.0 == response.header.id)
                            .unwrap();

                        let (_, client_address, original_request) =
                            request_queue.get(index).unwrap();

                        if original_request.header.qdcount > 1 {
                            println!(
                                "Looking for response with id {}, response_queue: {:?}",
                                response.header.id, response_queue
                            );
                            let response_index = response_queue
                                .iter()
                                .position(|x| x.0 == original_request.header.id);

                            if response_index.is_some() {
                                println!(
                                    "Index found for request id {}",
                                    original_request.header.id
                                );

                                let (_, address, existing_response) =
                                    response_queue.get(response_index.unwrap()).unwrap();
                                let mut existing_response = existing_response.clone();
                                existing_response.header.qdcount += 1;
                                existing_response.header.ancount += 1;

                                existing_response
                                    .questions
                                    .extend(response.questions.clone());
                                existing_response.answers.extend(response.answers.clone());

                                println!("existing_response: {:?}", existing_response);

                                if existing_response.header.ancount
                                    == original_request.header.qdcount
                                {
                                    println!(
                                        "Sending COMBINED response to {:?}: {:?}",
                                        address, existing_response
                                    );
                                    udp_socket
                                        .send_to(&existing_response.to_bytes(), address)
                                        .expect("Failed to send response");
                                } else {
                                    println!(
                                        "existing ancount = {}, original ancount = {}",
                                        existing_response.header.ancount,
                                        original_request.header.ancount
                                    );
                                }
                            } else {
                                println!("Inserting response with id {}", original_request.header.id);

                                response_queue.push((
                                    original_request.header.id,
                                    *client_address,
                                    response.clone(),
                                ));

                                println!("response_queue: {:?}", response_queue);
                            }
                        } else {
                            println!("Sending response to {:?}: {:?}", client_address, response);
                            udp_socket
                                .send_to(&response.to_bytes(), client_address)
                                .expect("Failed to send response");
                        }
                    }
                } else {
                    println!("Received query from {:?}: {:?}", source, request.clone());

                    if request.header.qdcount > 1 {
                        println!("Received a query with multiple questions. They will be broken down into multiple queries.");

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
