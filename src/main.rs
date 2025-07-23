use pcap::{Capture, Device};
use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

fn main() {
    let devices = match Device::list() {
        Ok(devices) => devices,
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
        Ok(cap) => cap,
        Err(err) => {
            eprintln!("Failed to open device {}: {}", device.name, err);
            return;
        }
    };

    println!("Capturing on interface {}...", device.name);

    while let Ok(packet) = cap.next_packet() {
        if let Err(err) = parse_and_print_packet(&packet.data) {
            eprintln!("Error parsing packet: {}", err);
        }
    }
} // main

// Print the list of devices to the console
fn print_device_list(devices: &[Device]) {
    println!("Available interfaces:");
    for (i, dev) in devices.iter().enumerate() {
        println!("  [{}] {}", i, dev.name);
    }
} // print_device_list

// Prompt user repeatedly until a valid device index is selected or 'q' to quit
fn prompt_device_selection(devices: &[Device]) -> usize {
    loop {
        print!("Select an interface by number or 'q' to quit: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            eprintln!("Failed to read input");
            continue;
        }

        let input = input.trim();

        if input.eq_ignore_ascii_case("q") {
            println!("Quitting");
            std::process::exit(0);
        }

        match input.parse::<usize>() {
            Ok(index) if index < devices.len() => return index,
            _ => eprintln!("Invalid selection"),
        }
    }
} // prompt_device_selection

// Opens a capture handle for the selected device
fn open_device_capture(device: &Device) -> Result<Capture<pcap::Active>, pcap::Error> {
    device.clone().open()
} // open_device_capture

// Parses a raw packet and prints meaningful info
fn parse_and_print_packet(data: &[u8]) -> Result<(), &'static str> {
    if data.len() < 14 {
        return Err("Packet too short for Ethernet header");
    }

    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    let src_mac = &data[6..12];
    let dst_mac = &data[0..6];

    print!("Ethernet frame: ");
    print!("Src MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ",
           src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    print!("Dst MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ",
           dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
    print!("Type 0x{:04x} ", ethertype);

    if ethertype == 0x0800 && data.len() >= 14 + 20 {
        let ip_header = &data[14..34];
        let version_ihl = ip_header[0];
        let version = version_ihl >> 4;

        if version == 4 {
            let total_length = u16::from_be_bytes([ip_header[2], ip_header[3]]);
            let protocol = ip_header[9];
            let src_ip = Ipv4Addr::new(ip_header[12], ip_header[13], ip_header[14], ip_header[15]);
            let dst_ip = Ipv4Addr::new(ip_header[16], ip_header[17], ip_header[18], ip_header[19]);

            print!("IPv4 src {} dst {} proto {} length {}",
                   src_ip, dst_ip, protocol, total_length);
        }
    } else if ethertype == 0x86DD && data.len() >= 14 + 40 {
        let ip_header = &data[14..54];
        let version = ip_header[0] >> 4;

        if version == 6 {
            let payload_length = u16::from_be_bytes([ip_header[4], ip_header[5]]);
            let next_header = ip_header[6];
            let src_ip = Ipv6Addr::new(
                u16::from_be_bytes([ip_header[8], ip_header[9]]),
                u16::from_be_bytes([ip_header[10], ip_header[11]]),
                u16::from_be_bytes([ip_header[12], ip_header[13]]),
                u16::from_be_bytes([ip_header[14], ip_header[15]]),
                u16::from_be_bytes([ip_header[16], ip_header[17]]),
                u16::from_be_bytes([ip_header[18], ip_header[19]]),
                u16::from_be_bytes([ip_header[20], ip_header[21]]),
                u16::from_be_bytes([ip_header[22], ip_header[23]]),
            );
            let dst_ip = Ipv6Addr::new(
                u16::from_be_bytes([ip_header[24], ip_header[25]]),
                u16::from_be_bytes([ip_header[26], ip_header[27]]),
                u16::from_be_bytes([ip_header[28], ip_header[29]]),
                u16::from_be_bytes([ip_header[30], ip_header[31]]),
                u16::from_be_bytes([ip_header[32], ip_header[33]]),
                u16::from_be_bytes([ip_header[34], ip_header[35]]),
                u16::from_be_bytes([ip_header[36], ip_header[37]]),
                u16::from_be_bytes([ip_header[38], ip_header[39]]),
            );

            print!("IPv6 src {} dst {} next_header {} payload_length {}",
                   src_ip, dst_ip, next_header, payload_length);
        }
    }

    println!();

    Ok(())
} // parse_and_print_packet
