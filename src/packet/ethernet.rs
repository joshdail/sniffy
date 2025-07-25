use super::{PacketInfo, PacketType};
use crate::packet::{ipv4, ipv6};

/// Entry point for parsing Ethernet-based packets.
pub fn parse_packet(data: &[u8]) -> Result<PacketInfo, &'static str> {
    if data.len() < 14 {
        return Err("Packet too short for Ethernet header");
    }

    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    let src_mac = array_from_slice(&data[6..12]);
    let dst_mac = array_from_slice(&data[0..6]);

    let mut info = PacketInfo {
        packet_type: PacketType::Ethernet,
        src_mac,
        dst_mac,
        src_ip: None,
        dst_ip: None,
        src_port: None,
        dst_port: None,
        tcp_flags: None,
        dns_queries: None,
    };

    match ethertype {
        0x0800 => ipv4::parse_ipv4(&data[14..], &mut info)?,
        0x86DD => ipv6::parse_ipv6(&data[14..], &mut info)?,
        other => info.packet_type = PacketType::Other(other),
    }

    Ok(info)
}

/// Utility: turn 6-byte slice into MAC array
pub fn array_from_slice(slice: &[u8]) -> Option<[u8; 6]> {
    if slice.len() == 6 {
        let mut arr = [0u8; 6];
        arr.copy_from_slice(slice);
        Some(arr)
    } else {
        None
    }
}
