use crate::packet::{PacketInfo, PacketType};
use std::net::Ipv6Addr;

pub fn parse_ipv6(payload: &[u8], info: &mut PacketInfo) -> Result<(), &'static str> {
    if payload.len() < 40 {
        return Err("IPv6 header too short");
    }

    let src = Ipv6Addr::from([
        payload[8], payload[9], payload[10], payload[11],
        payload[12], payload[13], payload[14], payload[15],
        payload[16], payload[17], payload[18], payload[19],
        payload[20], payload[21], payload[22], payload[23],
    ]);

    let dst = Ipv6Addr::from([
        payload[24], payload[25], payload[26], payload[27],
        payload[28], payload[29], payload[30], payload[31],
        payload[32], payload[33], payload[34], payload[35],
        payload[36], payload[37], payload[38], payload[39],
    ]);

    let next_header = payload[6];

    info.src_ip = Some(src.to_string());
    info.dst_ip = Some(dst.to_string());

    match next_header {
        6 => { // TCP
            if payload.len() < 40 + 20 {
                return Err("TCP header too short");
            }
            let (src_port, dst_port, flags) = crate::packet::tcp::parse_tcp_header(&payload[40..40 + 20])?;
            info.packet_type = PacketType::TCP;
            info.src_port = Some(src_port);
            info.dst_port = Some(dst_port);
            info.tcp_flags = Some(flags);
        }
        17 => { // UDP
            let udp_payload = &payload[40..];
            crate::packet::udp::parse_udp(udp_payload, info)?;
        }
        _ => {
            info.packet_type = PacketType::IPv6;
        }
    }

    Ok(())
}
