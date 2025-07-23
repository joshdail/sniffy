// src/ui/device.rs
use pcap::Device;
use std::io::{self, Write};

pub fn print_device_list(devices: &[Device]) {
    println!("Available interfaces:");
    for (i, dev) in devices.iter().enumerate() {
        println!("  [{}] {}", i, dev.name);
    }
}

pub fn prompt_device_selection(devices: &[Device]) -> usize {
    loop {
        print!("Select an interface by number (or 'q' to quit): ");
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
}
