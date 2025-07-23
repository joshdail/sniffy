use pcap::{Capture, Device};

pub fn open_device_capture(device: &Device) -> Result<Capture<pcap::Active>, pcap::Error> {
    return device.clone().open();
} // open_device_capture

pub fn prompt_and_apply_bpf_filter(cap: &mut Capture<pcap::Active>) {
    use std::io::{self, Write};

    loop {
        print!("Enter BPF filter (or press Enter to skip, or 'q' to quit): ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            eprintln!("Failed to read input");
            continue;
        }

        let filter = input.trim();

        if filter.eq_ignore_ascii_case("q") {
            println!("Quitting");
            std::process::exit(0);
        }

        if filter.is_empty() {
            println!("No filter applied");
            return;
        }

        match cap.filter(filter, true) {
            Ok (_) => {
                println!("Filter applied: {}", filter);
                return;
            }
            Err(err) => {
                eprintln!("Invalid filter: {}", err);
            }
        } // match cap.filter
    } // loop
} // prompt_and_apply_bpf_filter