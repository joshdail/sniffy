use super::{dns::parse_dns_queries, PacketInfo, PacketType};

/// Parses the UDP layer and updates the provided PacketInfo.
///
/// # Arguments
/// * `data` - The UDP segment (from IP payload)
/// * `info` - Mutable reference to the PacketInfo to populate
///
/// # Returns
/// * `Ok(())` if successful
/// * `Err(&'static str)` on failure
pub fn parse_udp(data: &[u8], info: &mut PacketInfo) -> Result<(), &'static str> {
    if data.len() < 8 {
        return Err("UDP packet too short");
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let udp_len  = u16::from_be_bytes([data[4], data[5]]); // includes header

    info.packet_type = PacketType::UDP;
    info.src_port = Some(src_port);
    info.dst_port = Some(dst_port);

    // Only parse if length is valid
    if udp_len as usize > data.len() {
        return Err("UDP length field exceeds packet size");
    }

    let payload = &data[8..udp_len as usize];

    // DNS detection: check if port 53 is involved
    if src_port == 53 || dst_port == 53 {
        if let Ok(queries) = parse_dns_queries(payload) {
            if !queries.is_empty() {
                info.packet_type = PacketType::DNS;
                info.dns_queries = Some(queries);
            }
        }
    }

    Ok(())
}
