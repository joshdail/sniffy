use clap::Parser;

/// Sniffy - Rust packet sniffer
#[derive(Parser, Debug)]
#[command(name = "sniffy", about = "Rust packet sniffer with optional PCAP export")]
pub struct CliArgs {
    /// Enable PCAP export and specify output file (optional).
    /// If no filename is provided, defaults to 'capture.pcap'.
    #[arg(long, value_name = "FILE")]
    pub export: Option<String>,
}
