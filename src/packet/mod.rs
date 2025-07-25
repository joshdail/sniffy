mod ethernet;
mod ipv4;
mod ipv6;
mod udp;
mod dns;
mod tcp;

pub use ethernet::*;
pub use ipv4::*;
pub use ipv6::*;
pub use tcp::*;
pub use udp::*;
pub use dns::*;

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub enum PacketType {
    Ethernet,
    IPv4,
    IPv6,
    TCP,
    UDP,
    DNS,
    Other(u16),
}

impl fmt::Display for PacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketType::Ethernet => write!(f, "Ethernet"),
            PacketType::IPv4 => write!(f, "IPv4"),
            PacketType::IPv6 => write!(f, "IPv6"),
            PacketType::TCP => write!(f, "TCP"),
            PacketType::UDP => write!(f, "UDP"),
            PacketType::DNS => write!(f, "DNS"),
            PacketType::Other(t) => write!(f, "Other EtherType 0x{:04x}", t),
        }
    }
}

#[derive(Debug)]
pub struct PacketInfo {
    pub packet_type: PacketType,
    pub src_mac: Option<[u8; 6]>,
    pub dst_mac: Option<[u8; 6]>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<TcpFlags>,
    pub dns_queries: Option<Vec<String>>,
}

pub fn parse_packet(data: &[u8]) -> Result<PacketInfo, &'static str> {
    ethernet::parse_packet(data)
}
