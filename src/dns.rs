#[allow(dead_code)]
#[derive(Debug, Default, Copy, Clone)]
#[repr(u16)]
pub enum Qtype {
    #[default]
    A = 1, // host address
    NS = 2,     // an authoritative name server
    MD = 3,     // a mail destination (Obsolete - use MX)
    MF = 4,     // a mail forwarder (Obsolete - use MX)
    CNAME = 5,  // the canonical name for an alias
    SOA = 6,    // marks the start of a zone of authority
    MB = 7,     // a mailbox domain name (EXPERIMENTAL)
    MG = 8,     // a mail group member (EXPERIMENTAL)
    MR = 9,     // a mail rename domain name (EXPERIMENTAL)
    NULL = 10,  // a null RR (EXPERIMENTAL)
    WKS = 11,   // a well known service description
    PTR = 12,   // a domain name pointer
    HINFO = 13, // host information
    MINFO = 14, // a mailbox or mail list information
    MX = 15,    // mail exchange
    TXT = 16,   // text strings
    // There's more
    ERROR = 256, // TODO: Use Result<T>
}

impl Qtype {
    pub fn from(value: u16) -> Qtype {
        match value {
            1 => Qtype::A,
            2 => Qtype::NS,
            3 => Qtype::MD,
            4 => Qtype::MF,
            5 => Qtype::CNAME,
            6 => Qtype::SOA,
            7 => Qtype::MB,
            8 => Qtype::MG,
            9 => Qtype::MR,
            10 => Qtype::NULL,
            11 => Qtype::WKS,
            12 => Qtype::PTR,
            13 => Qtype::HINFO,
            14 => Qtype::MINFO,
            15 => Qtype::MX,
            16 => Qtype::TXT,
            _ => Qtype::ERROR, // TODO: Use Result<T>
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Default, Copy, Clone)]
#[repr(u16)]
pub enum Qclass {
    #[default]
    IN = 1, // the Internet
    CS = 2,    // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH = 3,    // the CHAOS class
    HS = 4,    // Hesiod [Dyer 87]
    ANY = 255, // any class

    ERROR = 256,
}

impl Qclass {
    pub fn from(value: u16) -> Qclass {
        match value {
            1 => Qclass::IN,
            2 => Qclass::CS,
            3 => Qclass::CH,
            4 => Qclass::HS,
            255 => Qclass::ANY,
            _ => Qclass::ERROR,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct DnsHeader {
    // Packet ID (ID). 16 bits
    pub id: u16,
    // Query/Response indicator (QR). 1 bit
    pub qr: bool,
    // Operation code (OPCODE). 4 bits
    pub opcode: u8,
    // Authoritative answer (AA). 1 bit
    pub aa: bool,
    // Truncation (TC). 1 bit
    pub tc: bool,
    // Recursion desired (RD). 1 bit
    pub rd: bool,
    // Recursion available (RA). 1 bit
    pub ra: bool,
    // Reserved (Z). 3 bits
    pub z: u8,
    // Response code (RCODE). 4 bits
    pub rcode: u8,
    // Question count (QDCOUNT). 16 bits
    pub qdcount: u16,
    // Answer record count (ANCOUNT). 16 bits
    pub ancount: u16,
    // Authority record count (NSCOUNT). 16 bits
    pub nscount: u16,
    // Additional record count (ARCOUNT). 16 bits
    pub arcount: u16,
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            z: 0,
            rcode: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }
    pub fn parse(packet: Box<[u8]>) -> DnsHeader {
        DnsHeader {
            id: ((packet[0] as u16) << 8) | packet[1] as u16,
            qr: packet[2] & 0b10000000 != 0,
            opcode: (packet[2] & 0b01111000) >> 3,
            aa: packet[2] & 0b00000100 != 0,
            tc: packet[2] & 0b00001000 != 0,
            rd: packet[2] & 0b00000001 != 0,
            ra: packet[2] & 0b00100000 != 0,
            z: (packet[2] & 0b11000000) >> 6,
            rcode: packet[3] & 0b00001111,
            qdcount: ((packet[4] as u16) << 8) | packet[5] as u16,
            ancount: ((packet[6] as u16) << 8) | packet[7] as u16,
            nscount: ((packet[8] as u16) << 8) | packet[9] as u16,
            arcount: ((packet[10] as u16) << 8) | packet[11] as u16,
        }
    }

    pub fn to_bytes(&self) -> [u8; 12] {
        let mut packet = [0; 12];
        packet[0] = (self.id >> 8) as u8;
        packet[1] = self.id as u8;
        packet[2] = (self.qr as u8) << 7
            | (self.opcode << 3)
            | (self.aa as u8) << 2
            | (self.tc as u8) << 1
            | (self.rd as u8) << 0;
        packet[3] = (self.ra as u8) << 7 | (self.z << 4) | self.rcode;
        packet[4] = (self.qdcount >> 8) as u8;
        packet[5] = self.qdcount as u8;
        packet[6] = (self.ancount >> 8) as u8;
        packet[7] = self.ancount as u8;
        packet[8] = (self.nscount >> 8) as u8;
        packet[9] = self.nscount as u8;
        packet[10] = (self.arcount >> 8) as u8;
        packet[11] = self.arcount as u8;
        packet
    }
}

#[derive(Debug, Default, Clone)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: Qtype,
    pub qclass: Qclass,
}

fn decode_domain_name(array: Box<[u8]>) -> (String, usize) {
    let mut qname = String::new();
    let mut i = 0;
    while array[i] != 0 {
        let len = array[i] as usize;
        i += 1;
        let part = &array[i..i + len];
        qname += &String::from_utf8_lossy(part);
        i += len;

        if array[i] != 0 {
            qname.push('.');
        }
    }

    (qname, i as usize)
}

impl DnsQuestion {
    pub fn new(name: String, qtype: Qtype, qclass: Qclass) -> DnsQuestion {
        DnsQuestion {
            qname: name,
            qtype,
            qclass,
        }
    }

    pub fn parse(packet: Box<[u8]>, qdcount: u16) -> (Vec<DnsQuestion>, usize) {
        let mut questions: Vec<DnsQuestion> = Vec::new();

        let mut record_len: usize = 0;
        for i in 0..qdcount {
            let (qname, len) = decode_domain_name(
                packet[i as usize + record_len..]
                    .to_vec()
                    .into_boxed_slice(),
            );
            let qtype = packet[i as usize + len + 2];
            let qclass = packet[i as usize + len + 4];

            println!("qname: {}, qtype: {}, qclass: {}", qname, qtype, qclass);

            questions.push(DnsQuestion::new(
                qname,
                Qtype::from(qtype as u16),
                Qclass::from(qclass as u16),
            ));

            record_len += len + 4; // to account for qtype and qclass
        }

        (questions, record_len)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for part in self.qname.split('.') {
            bytes.push(part.len() as u8);
            bytes.extend(part.as_bytes());
        }
        bytes.push(0);
        bytes.push((self.qtype as u16 >> 8) as u8);
        bytes.push(self.qtype as u8);
        bytes.push((self.qclass as u16 >> 8) as u8);
        bytes.push(self.qclass as u8);
        bytes
    }
}

#[derive(Debug, Default, Clone)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    // pub authorities: Vec<DnsRecord>,
    // pub additionals: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: vec![],
            answers: vec![],
        }
    }

    pub fn parse(packet: Box<[u8]>) -> DnsPacket {
        let header = DnsHeader::parse(packet.clone());
        let (questions, question_len) =
            DnsQuestion::parse(packet[12..].to_vec().into_boxed_slice(), header.qdcount);
        let answers = DnsRecord::parse(
            packet[question_len..].to_vec().into_boxed_slice(),
            header.ancount,
        );
        DnsPacket {
            header,
            questions,
            answers,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.header.to_bytes());
        for question in &self.questions {
            bytes.extend(question.to_bytes());
        }
        for answer in &self.answers {
            bytes.extend(answer.to_bytes());
        }
        bytes
    }
}

#[derive(Debug, Default, Clone)]
pub struct DnsRecord {
    pub qname: String,
    pub qtype: Qtype,
    pub qclass: Qclass,
    pub ttl: u32,
    pub rdlen: u16,
    pub rdata: Vec<u8>,
}

impl DnsRecord {
    pub fn new(
        qname: String,
        qtype: Qtype,
        qclass: Qclass,
        ttl: u32,
        rdlen: u16,
        rdata: Vec<u8>,
    ) -> DnsRecord {
        DnsRecord {
            qname,
            qtype,
            qclass,
            ttl,
            rdlen,
            rdata,
        }
    }

    pub fn parse(packet: Box<[u8]>, ancount: u16) -> Vec<DnsRecord> {
        let mut answers: Vec<DnsRecord> = Vec::new();

        let mut record_len: usize = 0;
        for i in 0..ancount {
            let (qname, len) = decode_domain_name(
                packet[i as usize + record_len..]
                    .to_vec()
                    .into_boxed_slice(),
            );

            let qtype = packet[i as usize + len + 2];
            let qclass = packet[i as usize + len + 4];
            let ttl = packet[i as usize + len + 5] as u32;
            let rdlen = packet[i as usize + len + 6] as u16;
            let rdata =
                packet[i as usize + len + 6..i as usize + len + 6 + rdlen as usize].to_vec();

            println!(
                "qtype: {}, qclass: {}, ttl: {}, rdlen: {}, rdata: {:?}",
                qtype, qclass, ttl, rdlen, rdata
            );

            answers.push(DnsRecord::new(
                qname,
                Qtype::from(qtype as u16),
                Qclass::from(qclass as u16),
                ttl,
                rdlen,
                rdata,
            ));

            record_len += len + 4; // to account for qtype and qclass
        }

        answers
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for part in self.qname.split('.') {
            bytes.push(part.len() as u8);
            bytes.extend(part.as_bytes());
        }
        bytes.push(0);
        bytes.push((self.qtype as u16 >> 8) as u8);
        bytes.push(self.qtype as u8);
        bytes.push((self.qclass as u16 >> 8) as u8);
        bytes.push(self.qclass as u8);
        bytes.extend(self.ttl.to_be_bytes());
        bytes.extend(self.rdlen.to_be_bytes());
        bytes.extend(self.rdata.clone());
        bytes
    }
}
