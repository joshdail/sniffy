// src/packet/udp.rs

/// Parses a UDP header (minimum 8 bytes).
///
/// # Arguments
/// * `header` - A byte slice containing the UDP header (at least 8 bytes)
///
/// # Returns
/// * `Ok((src_port, dst_port, length))` on success
/// * `Err(&'static str)` on failure due to insufficient length
pub fn parse_udp_header(header: &[u8]) -> Result<(u16, u16, u16), &'static str> {
    if header.len() < 8 {
        return Err("UDP header too short");
    }

    let src_port = u16::from_be_bytes([header[0], header[1]]);
    let dst_port = u16::from_be_bytes([header[2], header[3]]);
    let length   = u16::from_be_bytes([header[4], header[5]]); // total length incl. header + data

    Ok((src_port, dst_port, length))
}
