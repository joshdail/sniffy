use std::net::{Ipv4Addr, Ipv6Addr};
use std::fmt;

#[derive(Hash, Eq, PartialEq, Debug)]
pub enum PacketType {
    Ethernet,
    IPv4,
    IPv6,
    Other(u16), // other Ethernet types
}

impl fmt::Display for PacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketType::Ethernet => write!(f, "Ethernet"),
            PacketType::IPv4 => write!(f, "IPv4"),
            PacketType::IPv6 => write!(f, "IPv6"),
            PacketType::Other(t) => write!(f, "Other EtherType 0x{:04x}", t),
        }
    }
}

pub fn parse_and_print_packet(data: &[u8]) -> Result<PacketType, &'static str> {
    if data.len() < 14 {
        return Err("Packet too short for Ethernet header");
    }

    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    let src_mac = &data[6..12];
    let dst_mac = &data[0..6];

    print!("Ethernet frame: ");
    print_mac("Src", src_mac);
    print_mac("Dst", dst_mac);
    print!("Type 0x{:04x} ", ethertype);

    let ptype = if ethertype == 0x0800 && data.len() >= 34 {
        print_ipv4(&data[14..34]);
        PacketType::IPv4
    } else if ethertype == 0x86DD && data.len() >= 54 {
        print_ipv6(&data[14..54]);
        PacketType::IPv6
    } else {
        PacketType::Other(ethertype)
    };

    println!();
    return Ok(ptype);
} // parse_and_print_packet

fn print_mac(label: &str, mac: &[u8]) {
    print!("{} MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ",
           label, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
} // print_mac

fn print_ipv4(header: &[u8]) {
    let total_length = u16::from_be_bytes([header[2], header[3]]);
    let protocol = header[9];
    let src = Ipv4Addr::new(header[12], header[13], header[14], header[15]);
    let dst = Ipv4Addr::new(header[16], header[17], header[18], header[19]);

    print!("IPv4 src {} dst {} proto {} length {}", src, dst, protocol, total_length);
} // print_ipv4

fn print_ipv6(header: &[u8]) {
    let payload_length = u16::from_be_bytes([header[4], header[5]]);
    let next_header = header[6];

    let src = Ipv6Addr::from([
        header[8], header[9], header[10], header[11], header[12], header[13], header[14], header[15],
        header[16], header[17], header[18], header[19], header[20], header[21], header[22], header[23],
    ]);

    let dst = Ipv6Addr::from([
        header[24], header[25], header[26], header[27], header[28], header[29], header[30], header[31],
        header[32], header[33], header[34], header[35], header[36], header[37], header[38], header[39],
    ]);

    print!("IPv6 src {} dst {} next_header {} payload_length {}", src, dst, next_header, payload_length);
} // print_ipv6