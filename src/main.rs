mod capture;
mod ui;
mod packet;

use capture::{open_device_capture, prompt_and_apply_bpf_filter};
use ui::{print_device_list, prompt_device_selection};
use packet::parse_and_print_packet;
use pcap::Device;

fn main() {
    let devices = match Device::list() {
        Ok(dlist) => dlist,
        Err(err) => {
            eprintln!("Failed to list devices: {}", err);
            return;
        }
    };

    print_device_list(&devices);

    let selected_index = prompt_device_selection(&devices);
    let device = &devices[selected_index];

    println!("Using device: {}", device.name);

    let mut cap = match open_device_capture(device) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("Failed to open device {}: {}", device.name, err);
            return;
        }
    };

    prompt_and_apply_bpf_filter(&mut cap);

    println!("Capturing on interface {}...", device.name);

    while let Ok(packet) = cap.next_packet() {
        if let Err(err) = parse_and_print_packet(&packet.data) {
            eprintln!("Error parsing packet: {}", err);
        }
    }
} // main