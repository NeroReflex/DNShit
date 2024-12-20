use crate::prelude::Error;
use crate::prelude::Result;

#[derive(Clone, Debug, PartialEq)]
pub struct DnsRequest {
    header: DnsHeader,
    questions: Vec<DnsQuestion>,
}

impl DnsRequest {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let header = DnsHeader::parse(&buf[0..12])?;
        let questions = parse_questions(&buf[12..], header.qdcount)?;

        Ok(
            Self {
                header,
                questions
            }
        )
    }

    pub fn header(&self) -> DnsHeader {
        self.header.clone()
    }

    pub fn questions(&self) -> Vec<DnsQuestion> {
        self.questions.clone()
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct DnsHeader {
    id: u16,
    qr: bool,
    opcode: u8,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: u8,
    rcode: u8,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl DnsHeader {
    pub fn parse(buf: &[u8]) -> crate::prelude::Result<Self> {
        let id = buf[0..2].try_into().map_err(|_| Error::ParseError)?;
        let qdcount = buf[4..6].try_into().map_err(|_| Error::ParseError)?;
        let ancount = buf[6..8].try_into().map_err(|_| Error::ParseError)?;
        let nscount = buf[8..10].try_into().map_err(|_| Error::ParseError)?;
        let arcount = buf[10..12].try_into().map_err(|_| Error::ParseError)?;

        Ok(
            Self {
                id: u16::from_be_bytes(id),
                qr: (buf[2] & 0b10000000) != 0,
                opcode: (buf[2] & 0b01111000) >> 3,
                aa: (buf[2] & 0b00000100) != 0,
                tc: (buf[2] & 0b00000010) != 0,
                rd: (buf[2] & 0b00000001) != 0,
                ra: (buf[3] & 0b10000000) != 0,
                z: (buf[3] & 0b01110000) >> 4,
                rcode: buf[3] & 0b00001111,
                qdcount: u16::from_be_bytes(qdcount),
                ancount: u16::from_be_bytes(ancount),
                nscount: u16::from_be_bytes(nscount),
                arcount: u16::from_be_bytes(arcount),
            }
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DnsQuestion {
    qname: String,
    qtype: u16,
    qclass: u16,
}

impl DnsQuestion {
    pub fn qname(&self) -> String {
        self.qname.clone()
    }

    pub fn qtype(&self) -> u16 {
        self.qtype
    }

    pub fn qclass(&self) -> u16 {
        self.qclass
    }

    fn parse_qname(buf: &[u8]) -> (String, usize) {
        let mut name = String::new();
        let mut offset = 0;
    
        while buf[offset] != 0 {
            let len = buf[offset] as usize;
            offset += 1;
            name.push_str(&String::from_utf8_lossy(&buf[offset..offset + len]));
            name.push('.');
            offset += len;
        }
    
        // Remove the trailing dot
        if !name.is_empty() {
            name.pop();
        }
    
        // Move past the null byte
        offset += 1;
    
        (name, offset)
    }

    pub fn parse(buf: &[u8]) -> Result<(Self, usize)> {
        let mut offset = 0;

        let (qname, len) = Self::parse_qname(&buf[offset..]);
        offset += len;
        let qtype = u16::from_be_bytes(buf[offset..offset + 2].try_into().map_err(|_err| Error::ParseError)?);
        offset += 2;
        let qclass = u16::from_be_bytes(buf[offset..offset + 2].try_into().map_err(|_err| Error::ParseError)?);
        offset += 2;

        Ok((Self { qname, qtype, qclass }, offset))
    }
}

fn parse_questions(buf: &[u8], qdcount: u16) -> Result<Vec<DnsQuestion>> {
    let mut questions = Vec::new();
    let mut offset = 0;

    for _ in 0..qdcount {
        let (parsed, offset_inc) = DnsQuestion::parse(&buf[offset..])?;

        offset += offset_inc;

        questions.push(parsed);
    }

    Ok(questions)
}

#[derive(Clone, Debug, PartialEq)]
struct DnsAnswer {
    name: String,
    qtype: u16,
    qclass: u16,
    ttl: u32,
    data_len: u16,
    address: [u8; 4], // Assuming IPv4
}

/// Use https://en.wikipedia.org/wiki/Domain_Name_System to build the answer
pub fn create_dns_response(header: DnsHeader, question: &DnsQuestion, ip_address: [u8; 4]) -> Vec<u8> {
    let mut response = Vec::new();

    // Construct the DNS header
    let mut header_bytes = Vec::new();
    header_bytes.extend(&header.id.to_be_bytes());

    let flags_1: u8 = /*if header.qr { 0x80 } else { 0x00 }*/ 0x80u8 | ((header.opcode & 0x0Fu8) << 3u8) | /*if header.aa { 0x04 } else { 0x00 }*/ 0x01u8 << 2u8 | if header.tc { 0x02 } else { 0x00 } | if header.rd { 0x01u8 } else { 0x00u8 };
    let flags_2: u8 = /*if header.ra { 0x80 } else { 0x00 }*/ 0x80u8 | /*if header.z {}*/ (header.rcode & 0x0fu8);

    println!("{} {}", flags_1, flags_2);

    header_bytes.push(flags_1);
    header_bytes.push(flags_2);
    header_bytes.extend(&header.qdcount.to_be_bytes());
    header_bytes.extend(&header.ancount.to_be_bytes());
    header_bytes.extend(&header.nscount.to_be_bytes());
    header_bytes.extend(&header.arcount.to_be_bytes());

    response.extend(header_bytes);

    let names = question.qname.split('.').into_iter().map(|e| String::from(e)).collect::<Vec<String>>();

    // Construct the question section
    for e in names {
        response.push(e.len() as u8);
        let qname_bytes = e.as_bytes();
        response.extend(qname_bytes);
    }
    response.push(0); // Null terminator for the qname
    response.extend(&question.qtype.to_be_bytes());
    response.extend(&question.qclass.to_be_bytes());

    // Construct the answer section
    let answer = DnsAnswer {
        name: question.qname.clone(),
        qtype: question.qtype,
        qclass: question.qclass,
        ttl: 300, // Time to live
        data_len: 4, // Length of the IPv4 address
        address: ip_address,
    };

    // Answer name (using compression, for simplicity we just repeat the name)
    /*response.extend(qname_bytes);*/
    response.push(0); // Null terminator for the name
    response.extend(&answer.qtype.to_be_bytes());
    response.extend(&answer.qclass.to_be_bytes());
    response.extend(&answer.ttl.to_be_bytes());
    response.extend(&answer.data_len.to_be_bytes());
    response.extend(&answer.address);

    response
}
