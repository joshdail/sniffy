use pcap::{Capture, Device};
use crate::ui::filter::prompt_for_bpf_filter;

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

/// Prompts the user for a BPF filter (or none), and applies it to the given capture.
///
/// # Arguments
/// * `cap` - A mutable reference to an active capture session
/// * `interface_name` - The name of the network interface (used to suggest filters)
///
/// # Panics
/// * If filter application fails (after validation), or the user chooses to quit
pub fn prompt_and_apply_bpf_filter(cap: &mut Capture<pcap::Active>, interface_name: &str) {
    if let Some(filter) = prompt_for_bpf_filter(interface_name) {
        match cap.filter(&filter, true) {
            Ok(_) => println!("Filter applied: {}", filter),
            Err(err) => {
                eprintln!("Invalid filter: {}", err);
                std::process::exit(1);
            }
        }
    } else {
        println!("No filter applied");
    }
}
