/// Represents parsed TCP flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags {
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

impl TcpFlags {
    pub fn from_byte(byte: u8) -> Self {
        Self {
            urg: byte & 0b0010_0000 != 0,
            ack: byte & 0b0001_0000 != 0,
            psh: byte & 0b0000_1000 != 0,
            rst: byte & 0b0000_0100 != 0,
            syn: byte & 0b0000_0010 != 0,
            fin: byte & 0b0000_0001 != 0,
        }
    }
}

impl std::fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut flags = vec![];
        if self.urg { flags.push("URG"); }
        if self.ack { flags.push("ACK"); }
        if self.psh { flags.push("PSH"); }
        if self.rst { flags.push("RST"); }
        if self.syn { flags.push("SYN"); }
        if self.fin { flags.push("FIN"); }

        write!(f, "{}", flags.join("|"))
    }
}

/// Parses the TCP header from the given byte slice.
///
/// # Arguments
/// * `header` - A slice containing at least the first 20 bytes of a TCP segment
///
/// # Returns
/// * A tuple: (source port, destination port, TCP flags) on success
/// * An error message on failure
pub fn parse_tcp_header(header: &[u8]) -> Result<(u16, u16, TcpFlags), &'static str> {
    if header.len() < 20 {
        return Err("TCP header too short");
    }

    let src_port = u16::from_be_bytes([header[0], header[1]]);
    let dst_port = u16::from_be_bytes([header[2], header[3]]);
    let flags = TcpFlags::from_byte(header[13]); // TCP flags are at byte offset 13

    Ok((src_port, dst_port, flags))
}
