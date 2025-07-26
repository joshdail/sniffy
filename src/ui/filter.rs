use std::io::{self, Write};

/// Represents a user quitting the program intentionally.
#[derive(Debug)]
pub struct QuitError;

impl std::fmt::Display for QuitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "User requested to quit")
    }
}

impl std::error::Error for QuitError {}

/// Returns a list of (description, BPF filter string) suggestions for the given interface.
pub fn get_bpf_filter_suggestions(interface_name: &str) -> Vec<(String, String)> {
    let is_loopback = interface_name.starts_with("lo")
        || interface_name.starts_with("utun")
        || interface_name.contains("loop");

    let mut filters = vec![
        ("All traffic (no filter)".to_string(), "".to_string()),
        ("TCP only".to_string(), "tcp".to_string()),
        ("UDP only".to_string(), "udp".to_string()),
        ("ICMP only".to_string(), "icmp".to_string()),
    ];

    if !is_loopback {
        filters.extend(vec![
            ("ARP traffic".to_string(), "arp".to_string()),
            ("Port 80 (HTTP)".to_string(), "port 80".to_string()),
            ("Port 443 (HTTPS)".to_string(), "port 443".to_string()),
            ("DNS traffic".to_string(), "port 53".to_string()),
        ]);
    } else {
        filters.push((
            "Loopback-only traffic (e.g. local apps)".to_string(),
            "ip and src net 127.0.0.1".to_string(),
        ));
    }

    filters
}