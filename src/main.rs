use configparser::ini::Ini;
use dnshit::dns::{create_dns_response, DnsRequest};
use dnshit::prelude::Error;
use rand::Rng;
use std::net::UdpSocket;
use std::sync::Mutex;
use std::{
    net::{IpAddr, ToSocketAddrs},
    sync::Arc,
};

#[derive(Clone, Debug, PartialEq)]
pub enum DnsLookupResult {
    Failed,
    Success(IpAddr),
}

fn handle_packet(
    listen_ip: String,
    dns_ip_port: String,
    packet: smallvec::SmallVec<[u8; 512]>,
) -> Result<Vec<Vec<u8>>, Error> {
    let req = DnsRequest::parse(packet.as_slice())?;

    let (header, questions) = (req.header(), req.questions());

    let lookups = questions
        .iter()
        .map(|q| {
            let hostname_with_port = q.qname() + ":555";

            if q.qtype() != 1 {
                // 1 is A (IPv4)
                return DnsLookupResult::Failed;
            }

            match hostname_with_port.as_str().to_socket_addrs() {
                Ok(a) => {
                    match a
                        .filter_map(|addr| {
                            match (addr.is_ipv4()) && (hostname_with_port.contains(".local")) {
                                true => Some(addr.ip()),
                                false => None,
                            }
                        })
                        .collect::<Vec<IpAddr>>()
                        .get(0)
                    {
                        Some(element) => {
                            println!("{} => {}", q.qname(), element);

                            DnsLookupResult::Success(element.clone())
                        }
                        None => DnsLookupResult::Failed,
                    }
                }
                Err(err) => {
                    eprintln!("Error in resolving {}: {}", q.qname(), err);

                    DnsLookupResult::Failed
                }
            }
        })
        .collect::<Vec<DnsLookupResult>>();

    match lookups
        .iter()
        .any(|lookup| matches!(lookup, DnsLookupResult::Failed))
    {
        true => {
            let random_port = rand::thread_rng().gen_range(1025..=u16::MAX);
            let random_port_str = random_port.to_string();

            let listen_host = listen_ip.clone() + ":" + random_port_str.as_str();

            match UdpSocket::bind(listen_host.as_str()) {
                Ok(forwarder_socket) => match forwarder_socket
                    .send_to(packet.as_slice(), dns_ip_port.clone())
                {
                    Ok(res) => {
                        if let Err(err) = forwarder_socket.set_read_timeout(Some(std::time::Duration::from_millis(1200))) {
                            return Err(Error::SocketUDPError { error: err });
                        }

                        if let Err(err) = forwarder_socket.set_write_timeout(Some(std::time::Duration::from_millis(1200))) {
                            return Err(Error::SocketUDPError { error: err });
                        }

                        println!("Sent {} bytes to {}", res, dns_ip_port.clone());

                        let mut buf = [0u8; 512];
                        match forwarder_socket.recv_from(&mut buf) {
                            Ok((size, src)) => {
                                println!("DNS server {} answered with {} bytes", src, size);

                                let answer =
                                    smallvec::SmallVec::<[u8; 512]>::from_buf_and_len(buf, size);
                                Ok(vec![answer.to_vec()])
                            }
                            Err(err) => {
                                eprintln!(
                                    "Error receiving answer to the forwarded DNS query: {}",
                                    err
                                );

                                Err(Error::ForwardingError { error: err })
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!(
                            "Error forwarding DNS request to {}: {}",
                            dns_ip_port.clone(),
                            err
                        );

                        Err(Error::ForwardingError { error: err })
                    }
                },
                Err(err) => {
                    eprintln!("Error opening an UDP socket: {}", err);

                    Err(Error::SocketUDPError { error: err })
                }
            }
        }
        false => Ok(lookups
            .iter()
            .enumerate()
            .map(|(idx, lookup_result)| match lookup_result {
                DnsLookupResult::Success(s) => match s {
                    IpAddr::V4(v4) => {
                        create_dns_response(header, questions.get(idx).unwrap(), v4.octets())
                    }
                    IpAddr::V6(_v6) => unreachable!(),
                },
                DnsLookupResult::Failed => unreachable!(),
            })
            .collect()),
    }
}

fn main() -> std::io::Result<()> {
    let mut config = Ini::new();
    let map = config.load("settings.ini");
    match map {
        Ok(_m) => {}
        Err(err) => {
            eprintln!("Error loading the file settings.init: {}", err);
            panic!();
        }
    }

    let listen_socket_addr = config.get("general", "listen_socket_addr");
    let dns_server_addr = config.get("general", "dns_server_addr");

    match (listen_socket_addr, dns_server_addr) {
        (Some(listen_ip), Some(dns_ip_port)) => {
            let socket = Arc::new(Mutex::new(
                UdpSocket::bind((listen_ip.clone() + ":53").as_str()).unwrap(),
            ));

            let mut buf = [0u8; 512]; // Buffer for incoming packets

            loop {
                println!("Waiting for DNS packet...");

                // Receive a packet
                if let Ok(sock_guard) = socket.lock() {
                    let (len, incoming_addr) = sock_guard.recv_from(&mut buf)?;
                    println!("Received {} bytes from {}", len, incoming_addr);

                    let packet = smallvec::SmallVec::from_buf_and_len(buf, len);

                    let listen_ip_clone = listen_ip.clone();
                    let dns_ip_port_clone = dns_ip_port.clone();

                    match handle_packet(listen_ip_clone, dns_ip_port_clone, packet) {
                        Ok(answers) => answers
                            .iter()
                            .map(|response| {
                                match sock_guard.send_to(response.as_slice(), incoming_addr) {
                                    Ok(sent) => {
                                        println!(
                                            "Answered to {} with {} bytes",
                                            incoming_addr, sent
                                        );
                                    }
                                    Err(err) => {
                                        eprintln!("Error forwarding the response: {}", err);
                                    }
                                }
                            })
                            .collect(),
                        Err(err) => {
                            eprintln!("Error parsing DNS request: {}", err);
                        }
                    }
                };
            }
        }
        _ => panic!(
            "Unspecified listen_socket_addr or dns_server_addr: they have to be an IP address"
        ),
    }
}
