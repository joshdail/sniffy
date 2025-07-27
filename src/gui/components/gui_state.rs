/// Represents the state of the packet capture engine
#[derive(Debug, PartialEq, Eq)]
pub enum CaptureState {
    Idle,
    Capturing,
}

/// Represents the kind of interface detected
#[derive(Debug, PartialEq, Eq)]
pub enum InterfaceKind {
    Loopback,
    Ethernet,
    Unknown,
}

/// Detects the interface kind based on name heuristics
pub fn detect_interface_type(name: &str) -> InterfaceKind {
    if name.contains("lo") {
        InterfaceKind::Loopback
    } else if name.contains("en") || name.contains("eth") {
        InterfaceKind::Ethernet
    } else {
        InterfaceKind::Unknown
    }
}

/// Returns a list of common BPF filters based on the interface type
pub fn suggested_filters(interface: &str) -> Vec<String> {
    match detect_interface_type(interface) {
        InterfaceKind::Loopback => vec![
            "tcp".into(),
            "udp".into(),
            "port 53".into(),
            "ip".into(),
            "icmp".into(),
        ],
        InterfaceKind::Ethernet => vec![
            "tcp".into(),
            "udp".into(),
            "port 80".into(),
            "port 443".into(),
            "port 53".into(),
            "ip".into(),
            "icmp".into(),
        ],
        InterfaceKind::Unknown => vec!["ip".into(), "tcp".into()],
    }
}
