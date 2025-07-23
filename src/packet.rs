use std::net::{Ipv4Addr, Ipv6Addr};
use std::fmt;

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub enum PacketType {
    Ethernet,
    IPv4,
    IPv6,
    TCP,
    UDP,
    DNS,
    Other(u16), // other Ethernet types
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

/// A structured representation of parsed packet info, for easier UI integration
#[derive(Debug)]
pub struct PacketInfo {
    pub packet_type: PacketType,
    pub src_mac: Option<[u8; 6]>,
    pub dst_mac: Option<[u8; 6]>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<u8>,
    pub dns_queries: Option<Vec<String>>,
}

/// Parse a raw packet buffer and return structured `PacketInfo` or error string
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
        0x0800 => { // IPv4
            if data.len() < 34 {
                return Err("Packet too short for IPv4 header");
            }
            let ip_header = &data[14..34];
            let (src_ip, dst_ip, protocol) = parse_ipv4_header(ip_header)?;
            info.src_ip = Some(src_ip.to_string());
            info.dst_ip = Some(dst_ip.to_string());

            match protocol {
                6 => { // TCP
                    if data.len() < 54 {
                        return Err("Packet too short for TCP header");
                    }
                    let tcp_header = &data[34..54];
                    let (src_port, dst_port, flags) = parse_tcp_header(tcp_header)?;
                    info.packet_type = PacketType::TCP;
                    info.src_port = Some(src_port);
                    info.dst_port = Some(dst_port);
                    info.tcp_flags = Some(flags);
                }
                17 => { // UDP
                    if data.len() < 42 {
                        return Err("Packet too short for UDP header");
                    }
                    let udp_header = &data[34..42];
                    let (src_port, dst_port, _length) = parse_udp_header(udp_header)?;
                    info.src_port = Some(src_port);
                    info.dst_port = Some(dst_port);

                    // Check DNS
                    if src_port == 53 || dst_port == 53 {
                        info.packet_type = PacketType::DNS;
                        // Try to parse DNS queries (optional, best effort)
                        if data.len() > 42 {
                            let dns_payload = &data[42..];
                            info.dns_queries = parse_dns_queries(dns_payload).ok();
                        }
                    } else {
                        info.packet_type = PacketType::UDP;
                    }
                }
                _ => info.packet_type = PacketType::IPv4,
            }
        }
        0x86DD => { // IPv6
            if data.len() < 54 {
                return Err("Packet too short for IPv6 header");
            }
            let ip_header = &data[14..54];
            let (src_ip, dst_ip, next_header) = parse_ipv6_header(ip_header)?;
            info.src_ip = Some(src_ip.to_string());
            info.dst_ip = Some(dst_ip.to_string());

            let payload_start = 54;
            match next_header {
                6 => { // TCP
                    if data.len() < payload_start + 20 {
                        return Err("Packet too short for TCP header");
                    }
                    let tcp_header = &data[payload_start..payload_start + 20];
                    let (src_port, dst_port, flags) = parse_tcp_header(tcp_header)?;
                    info.packet_type = PacketType::TCP;
                    info.src_port = Some(src_port);
                    info.dst_port = Some(dst_port);
                    info.tcp_flags = Some(flags);
                }
                17 => { // UDP
                    if data.len() < payload_start + 8 {
                        return Err("Packet too short for UDP header");
                    }
                    let udp_header = &data[payload_start..payload_start + 8];
                    let (src_port, dst_port, _length) = parse_udp_header(udp_header)?;
                    info.src_port = Some(src_port);
                    info.dst_port = Some(dst_port);

                    // Check DNS
                    if src_port == 53 || dst_port == 53 {
                        info.packet_type = PacketType::DNS;
                        if data.len() > payload_start + 8 {
                            let dns_payload = &data[payload_start + 8..];
                            info.dns_queries = parse_dns_queries(dns_payload).ok();
                        }
                    } else {
                        info.packet_type = PacketType::UDP;
                    }
                }
                _ => info.packet_type = PacketType::IPv6,
            }
        }
        other => {
            info.packet_type = PacketType::Other(other);
        }
    }

    Ok(info)
}

// Helpers

fn array_from_slice(slice: &[u8]) -> Option<[u8; 6]> {
    if slice.len() == 6 {
        let mut arr = [0u8; 6];
        arr.copy_from_slice(slice);
        Some(arr)
    } else {
        None
    }
}

fn parse_ipv4_header(header: &[u8]) -> Result<(Ipv4Addr, Ipv4Addr, u8), &'static str> {
    if header.len() < 20 {
        return Err("IPv4 header too short");
    }
    let src = Ipv4Addr::new(header[12], header[13], header[14], header[15]);
    let dst = Ipv4Addr::new(header[16], header[17], header[18], header[19]);
    let protocol = header[9];
    Ok((src, dst, protocol))
}

fn parse_ipv6_header(header: &[u8]) -> Result<(Ipv6Addr, Ipv6Addr, u8), &'static str> {
    if header.len() < 40 {
        return Err("IPv6 header too short");
    }
    let src = Ipv6Addr::from([
        header[8], header[9], header[10], header[11], header[12], header[13], header[14], header[15],
        header[16], header[17], header[18], header[19], header[20], header[21], header[22], header[23],
    ]);
    let dst = Ipv6Addr::from([
        header[24], header[25], header[26], header[27], header[28], header[29], header[30], header[31],
        header[32], header[33], header[34], header[35], header[36], header[37], header[38], header[39],
    ]);
    let next_header = header[6];
    Ok((src, dst, next_header))
}

fn parse_tcp_header(header: &[u8]) -> Result<(u16, u16, u8), &'static str> {
    if header.len() < 20 {
        return Err("TCP header too short");
    }
    let src_port = u16::from_be_bytes([header[0], header[1]]);
    let dst_port = u16::from_be_bytes([header[2], header[3]]);
    let flags = header[13];
    Ok((src_port, dst_port, flags))
}

fn parse_udp_header(header: &[u8]) -> Result<(u16, u16, u16), &'static str> {
    if header.len() < 8 {
        return Err("UDP header too short");
    }
    let src_port = u16::from_be_bytes([header[0], header[1]]);
    let dst_port = u16::from_be_bytes([header[2], header[3]]);
    let length = u16::from_be_bytes([header[4], header[5]]);
    Ok((src_port, dst_port, length))
}

/// Very basic DNS query name parsing (best effort).
/// Parses the first DNS query name from the DNS payload.
/// Returns list of queries as Vec<String>.
fn parse_dns_queries(payload: &[u8]) -> Result<Vec<String>, &'static str> {
    if payload.len() < 12 {
        return Err("DNS payload too short");
    }
    // DNS header is 12 bytes, next is queries
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return Ok(vec![]);
    }

    let mut queries = Vec::new();
    let mut offset = 12;

    for _ in 0..qdcount {
        let (name, next_offset) = parse_dns_name(payload, offset)?;
        queries.push(name);
        // Skip QTYPE(2 bytes) + QCLASS(2 bytes)
        offset = next_offset + 4;
        if offset > payload.len() {
            break;
        }
    }

    Ok(queries)
}

/// Parses a DNS name at given offset in the payload.
/// Returns the name as string and new offset after the name.
fn parse_dns_name(payload: &[u8], mut offset: usize) -> Result<(String, usize), &'static str> {
    let mut labels = Vec::new();

    while offset < payload.len() {
        let len = payload[offset] as usize;
        offset += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            // DNS pointer (compression) not handled in this basic parser
            return Err("DNS name compression not supported");
        }
        if offset + len > payload.len() {
            return Err("DNS name label exceeds payload length");
        }
        let label = std::str::from_utf8(&payload[offset..offset + len])
            .map_err(|_| "Invalid UTF-8 in DNS label")?;
        labels.push(label.to_string());
        offset += len;
    }

    Ok((labels.join("."), offset))
}
