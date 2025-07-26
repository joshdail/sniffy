use crate::capture::open_device_capture;
use pcap::{Capture, Device};

/// Initializes and returns a list of available capture devices.
/// Used for populating the TUI device selector.
pub fn get_available_devices() -> Result<Vec<Device>, String> {
    Device::list().map_err(|e| format!("Failed to list devices: {}", e))
}

/// Opens an active capture session for a given device name.
/// Reinitializes a capture session for the given device name.
/// Used when user selects a different device from the TUI.
///
/// # Returns
/// A new `Capture<pcap::Active>` on success, or a `String` error message.
pub fn reinitialize_capture(device_name: &str) -> Result<Capture<pcap::Active>, String> {
    let devices = Device::list()
        .map_err(|e| format!("Failed to list devices: {}", e))?;

    let device = devices
        .into_iter()
        .find(|d| d.name == device_name)
        .ok_or_else(|| format!("Device '{}' not found", device_name))?;

    // Do not use println! inside TUI mode
    open_device_capture(&device)
        .map_err(|e| format!("Failed to open device {}: {}", device.name, e))
}