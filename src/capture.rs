use pcap::{Capture, Device};
use crate::ui::filter::QuitError;

/// Opens a packet capture session on the given device with non-blocking mode enabled.
///
/// # Arguments
/// * `device` - The selected network device
///
/// # Returns
/// * A `Capture<pcap::Active>` object on success, or a `pcap::Error` on failure
pub fn open_device_capture(device: &Device) -> Result<Capture<pcap::Active>, pcap::Error> {
    let cap = device.clone().open()?;
    let cap = cap.setnonblock()?;  // Enable non-blocking mode by taking ownership properly
    Ok(cap)
}
