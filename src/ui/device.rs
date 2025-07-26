use pcap::{Device, Error as PcapError};
use std::error::Error;
use std::io::{self, Write};
use crate::ui::filter::QuitError; // Reuse shared quit signal type

/// Returns all non-loopback device names.
pub fn get_available_devices() -> Result<Vec<String>, PcapError> {
    let devices = Device::list()?;
    let filtered = devices
        .into_iter()
        .filter(|d| !d.name.contains("lo") && !d.name.contains("Loopback"))
        .map(|d| d.name)
        .collect();
    Ok(filtered)
}
