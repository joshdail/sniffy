use eframe::egui::Color32;
use crate::packet::PacketType;

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

/// UI-focused protocol display info: label + color
pub enum ProtocolDisplay {
    DNS,
    TCP,
    UDP,
    IPv4,
    IPv6,
    Ethernet,
    Other,
}

impl ProtocolDisplay {
    /// Map PacketType to ProtocolDisplay
    pub fn from_packet_type(packet_type: PacketType) -> Self {
        match packet_type {
            PacketType::DNS => ProtocolDisplay::DNS,
            PacketType::TCP => ProtocolDisplay::TCP,
            PacketType::UDP => ProtocolDisplay::UDP,
            PacketType::IPv4 => ProtocolDisplay::IPv4,
            PacketType::IPv6 => ProtocolDisplay::IPv6,
            PacketType::Ethernet => ProtocolDisplay::Ethernet,
            PacketType::Other(_) => ProtocolDisplay::Other,
        }
    }

    /// The label text to show in the UI
    pub fn label(&self) -> &'static str {
        match self {
            ProtocolDisplay::DNS => "DNS:",
            ProtocolDisplay::TCP => "TCP:",
            ProtocolDisplay::UDP => "UDP:",
            ProtocolDisplay::IPv4 => "IPv4:",
            ProtocolDisplay::IPv6 => "IPv6:",
            ProtocolDisplay::Ethernet => "Ethernet:",
            ProtocolDisplay::Other => "Other:",
        }
    }

    /// The color for the protocol label
    pub fn color(&self) -> Color32 {
        match self {
            ProtocolDisplay::DNS => Color32::from_rgb(0, 150, 0),          // Green
            ProtocolDisplay::TCP => Color32::from_rgb(0, 128, 255),        // Blue
            ProtocolDisplay::UDP => Color32::YELLOW,                        // Yellow
            ProtocolDisplay::IPv4 | ProtocolDisplay::IPv6 => Color32::LIGHT_GRAY,
            ProtocolDisplay::Ethernet => Color32::from_rgb(180, 180, 180), // Light Gray
            ProtocolDisplay::Other => Color32::DARK_GRAY,
        }
    }
}
