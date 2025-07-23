use crate::capture::{open_device_capture, prompt_and_apply_bpf_filter};
use crate::ui::{print_device_list, prompt_device_selection};
use pcap::{Capture, Device};

pub fn initialize_capture() -> Result<Capture<pcap::Active>, String> {
    let devices = Device::list().map_err(|e| format!("Failed to list devices: {}", e))?;

    print_device_list(&devices);

    let selected_index = prompt_device_selection(&devices);
    let device = &devices[selected_index];

    println!("Using device: {}", device.name);

    let mut cap = open_device_capture(device)
        .map_err(|e| format!("Failed to open device {}: {}", device.name, e))?;

    prompt_and_apply_bpf_filter(&mut cap);
    println!("Capturing on interface {}... Press Ctrl+C to stop and see summary", device.name);

    Ok(cap)
} // initialize_capture
