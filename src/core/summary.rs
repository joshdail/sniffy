use crate::packet::PacketType;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::io::{self, Write};
use std::{thread, time};

/// Prints a summary of captured packets by type.
///
/// # Arguments
///
/// * `counts` - Shared packet count map wrapped in `Arc<Mutex<_>>`
pub fn print_packet_summary(counts: Arc<Mutex<HashMap<PacketType, usize>>>) {
    println!("\n\nPacket summary:");

    let counts = counts.lock().unwrap();

    if counts.is_empty() {
        println!("No packets captured");
    } else {
        for (ptype, count) in counts.iter() {
            println!("  {}: {}", ptype, count);
        }
    }

    // Ensure output is fully flushed before exiting
    io::stdout().flush().unwrap();
    thread::sleep(time::Duration::from_millis(100));
}
