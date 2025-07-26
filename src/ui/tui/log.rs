use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use crate::packet::{PacketInfo, PacketType};

static MAX_LINES: usize = 30;

// Shared packet log queue (thread-safe)
lazy_static::lazy_static! {
    pub static ref PACKET_LOG: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(VecDeque::new()));
}

/// Adds a formatted packet line to the shared log.
pub fn display_packet_info(info: &PacketInfo) {
    let summary = format_packet_line(info);
    let mut log = PACKET_LOG.lock().unwrap();
    log.push_back(summary);
    if log.len() > MAX_LINES {
        log.pop_front();
    }
}

/// Prints a final summary of packet counts after capture ends.
pub fn print_final_summary(counts: Arc<Mutex<HashMap<PacketType, usize>>>) {
    // Disable raw mode and restore terminal state if needed (done in main thread)
    // Here, just print summary:
    println!("\nPacket summary:");
    let counts = counts.lock().unwrap();
    for (ptype, count) in counts.iter() {
        println!("  {}: {}", ptype, count);
    }
}

fn format_packet_line(info: &PacketInfo) -> String {
    let macs = match (&info.src_mac, &info.dst_mac) {
        (Some(src), Some(dst)) => format!("MAC {} -> {}", mac_to_str(src), mac_to_str(dst)),
        _ => "MAC [n/a]".to_string(),
    };

    let ips = match (&info.src_ip, &info.dst_ip) {
        (Some(src), Some(dst)) => format!("{} -> {}", src, dst),
        _ => "[no IP]".to_string(),
    };

    let ports = match (info.src_port, info.dst_port) {
        (Some(s), Some(d)) => format!("ports {} -> {}", s, d),
        _ => String::new(),
    };

    let mut summary = format!("{} | {} | {} | {}", info.packet_type, macs, ips, ports);

    if let Some(flags) = &info.tcp_flags {
        summary.push_str(&format!(" | TCP Flags: [{}]", flags));
    }

    if let Some(queries) = &info.dns_queries {
        summary.push_str(&format!(" | DNS: {}", queries.join(", ")));
    }

    summary
}

fn mac_to_str(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
