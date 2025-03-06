#[derive(Debug, Default, Clone)]
pub struct DnsHeader {
    // Packet ID (ID). 16 bits
    pub  id: u16,
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
            rd: packet[2] & 0b00010000 != 0,
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
