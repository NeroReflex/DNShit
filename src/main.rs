use dnshit::dns::{create_dns_response, DnsRequest};
use configparser::ini::Ini;
use tokio::net::UdpSocket;
use tokio::time;
use std::net::{IpAddr, ToSocketAddrs};
use rand::Rng;

#[derive(Clone, Debug, PartialEq)]
pub enum DnsLookupResult {
    Failed,
    Success(IpAddr),
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut config = Ini::new();
    let map = config.load("settings.ini");
    match map {
        Ok(_m) => {},
        Err(err) => {eprintln!("Error loading the file settings.init: {}", err); panic!(); }
    }

    let listen_socket_addr = config.get("general", "listen_socket_addr");
    let dns_server_addr = config.get("general", "dns_server_addr");
    
    match (listen_socket_addr, dns_server_addr) {
        (Some(listen_ip), Some(dns_ip_port)) => {
            let socket = UdpSocket::bind((listen_ip.clone() + ":53").as_str()).await?;

            let mut buf = [0u8; 512]; // Buffer for incoming packets

            // Create a random number generator
            let mut rng = rand::thread_rng();

            loop {
                // Receive a packet
                let (len, incoming_addr) = socket.recv_from(&mut buf).await?;
                println!("Received {} bytes from {}", len, incoming_addr);

                let packet = smallvec::SmallVec::from_buf_and_len(buf, len);

                match DnsRequest::parse(&buf) {
                    Ok(req) => {
                        let (header, questions) = (req.header(), req.questions());

                        let lookups = questions.iter().map(|q| {
                            let hostname_with_port = q.qname() + ":555";
                
                            if (q.qtype() != 1) { // 1 is A (IPv4)
                                return DnsLookupResult::Failed;
                            }

                            match hostname_with_port.as_str().to_socket_addrs() {
                                Ok(a) => {
                                    match a.filter_map(|addr| match (addr.is_ipv4()) && (hostname_with_port.contains(".local")) {
                                        true => Some(addr.ip()),
                                        false => None
                                    }).collect::<Vec<IpAddr>>().get(0) {
                                        Some(element) => {
                                            println!("{} => {}", q.qname(), element);
                
                                            DnsLookupResult::Success(element.clone())
                                        },
                                        None => DnsLookupResult::Failed
                                    }
                                },
                                Err(err) => {
                                    eprintln!("Error in resolving {}: {}", q.qname(), err);
                
                                    DnsLookupResult::Failed
                                }
                            }
                        }).collect::<Vec<DnsLookupResult>>();
                
                        match lookups.iter().any(|lookup| matches!(lookup, DnsLookupResult::Failed)) {
                            true => {
                                let random_port = rng.gen_range(1025..=u16::MAX);
                                let random_port_str = random_port.to_string();
                                
                                let listen_host = listen_ip.clone() + ":" + random_port_str.as_str();
                
                                match UdpSocket::bind(listen_host.as_str()).await {
                                    Ok(forwarder_socket) => match forwarder_socket.send_to(packet.as_slice(), dns_ip_port.clone()).await {
                                        Ok(res) => {
                                            println!("Sent {} bytes to {}", res, dns_ip_port.clone());
                    
                                            match time::timeout(time::Duration::from_secs(1), forwarder_socket.recv_from(&mut buf)).into_inner().await {
                                                Ok((size, src)) => {
                                                    println!("DNS server {} answered with {} bytes", src, size);
                    
                                                    let answer = smallvec::SmallVec::<[u8; 512]>::from_buf_and_len(buf, size);
                                                    match socket.send_to(answer.as_slice(), incoming_addr).await {
                                                        Ok(sent) => {
                                                            println!("Answered to {} with {} bytes", incoming_addr, sent)
                                                        },
                                                        Err(err) => {
                                                            eprintln!("Error forwarding the response: {}", err);
                                                        }
                                                    }
                                                },
                                                Err(err) => {
                                                    eprintln!("Error receiving answer to the forwarded DNS query: {}", err)
                                                }
                                            }
                                        },
                                        Err(err) => {
                                            eprintln!("Error forwarding DNS request to {}: {}", dns_ip_port.clone(), err);
                                        },
                                    },
                                    Err(err) => {
                                        eprintln!("Error opening an UDP socket: {}", err);
                                    }
                                }
                            },
                            false => {
                                for (idx, lookup_result) in lookups.iter().enumerate() {
                                    match lookup_result {
                                        DnsLookupResult::Success(s) => {
                                            match s {
                                                IpAddr::V4(v4) => {
                                                    let response = create_dns_response(header, questions.get(idx).unwrap(), v4.octets());
                
                                                    match socket.send_to(response.as_slice(), incoming_addr).await {
                                                        Ok(sent) => {
                                                            println!("Answered to {} with {} bytes", incoming_addr, sent)
                                                        },
                                                        Err(err) => {
                                                            eprintln!("Error forwarding the response: {}", err);
                                                        }
                                                    }
                                                },
                                                IpAddr::V6(_v6) => unreachable!()
                                            }
                                        },
                                        DnsLookupResult::Failed => unreachable!()
                                    }
                                }
                            }
                        }
                    },
                    Err(err) => {
                        eprintln!("Error parsing DNS request: {}", err);
                    }
                }
            }
        },
        _ => panic!("Unspecified listen_socket_addr or dns_server_addr: they have to be an IP address")
    }
}
