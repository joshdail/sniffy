use crate::packet::{PacketInfo, PacketType};
use std::net::Ipv4Addr;

pub fn parse_ipv4(payload: &[u8], info: &mut PacketInfo) -> Result<(), &'static str> {
    if payload.len() < 20 {
        return Err("IPv4 header too short");
    }

    let ihl = payload[0] & 0x0F;
    let ip_header_len = (ihl as usize) * 4;

    if payload.len() < ip_header_len {
        return Err("IPv4 header length exceeds payload size");
    }

    let src = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
    let dst = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
    let protocol = payload[9];

    info.src_ip = Some(src.to_string());
    info.dst_ip = Some(dst.to_string());

    match protocol {
        6 => { // TCP
            if payload.len() < ip_header_len + 20 {
                return Err("TCP header too short");
            }
            let (src_port, dst_port, flags) = crate::packet::tcp::parse_tcp_header(&payload[ip_header_len..ip_header_len + 20])?;
            info.packet_type = PacketType::TCP;
            info.src_port = Some(src_port);
            info.dst_port = Some(dst_port);
            info.tcp_flags = Some(flags);
        }
        17 => { // UDP
            let udp_payload = &payload[ip_header_len..];
            crate::packet::udp::parse_udp(udp_payload, info)?;
        }
        _ => {
            info.packet_type = PacketType::IPv4;
        }
    }

    Ok(())
}
