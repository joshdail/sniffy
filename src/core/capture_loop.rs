use crate::capture::open_device_capture;
use pcap::{Capture, Device};

/// Returns a list of available network capture devices.
pub fn get_available_devices() -> Result<Vec<Device>, String> {
    Device::list().map_err(|e| format!("Failed to list devices: {}", e))
}

/// Opens a new capture session for the given device name.
/// This function ensures the device exists before attempting to open it.
pub fn reinitialize_capture(device_name: &str) -> Result<Capture<pcap::Active>, String> {
    let device = Device::list()
        .map_err(|e| format!("Failed to list devices: {}", e))?
        .into_iter()
        .find(|d| d.name == device_name)
        .ok_or_else(|| format!("Device '{}' not found", device_name))?;

    open_device_capture(&device)
        .map_err(|e| format!("Failed to open device {}: {}", device.name, e))
}

/// Applies a BPF filter to the provided active capture session.
/// Returns `Ok(())` on success, or a formatted error string on failure.
pub fn apply_bpf_filter(
    cap: &mut Capture<pcap::Active>,
    filter: &str,
) -> Result<(), String> {
    if filter.trim().is_empty() {
        return Ok(()); // Empty filter is valid (no-op)
    }

    cap.filter(filter, true)
        .map_err(|e| format!("Failed to apply BPF filter '{}': {}", filter, e))
}
