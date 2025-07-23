use std::io::{self, Write};

/// Prompt the user to select or enter a BPF filter based on the interface type.
pub fn prompt_for_bpf_filter(interface_name: &str) -> Option<String> {
    let is_loopback = interface_name.starts_with("lo") || interface_name.starts_with("utun") || interface_name.contains("loop");

    let mut filters = vec![
        ("All traffic", ""),
        ("TCP only", "tcp"),
        ("UDP only", "udp"),
        ("ICMP only", "icmp"),
    ];

    if !is_loopback {
        filters.extend(&[
            ("ARP traffic", "arp"),
            ("Port 80 (HTTP)", "port 80"),
            ("Port 443 (HTTPS)", "port 443"),
        ]);
    } else {
        filters.push(("Loopback-only traffic (e.g. local apps)", "ip and src net 127.0.0.1"));
    }

    println!("\n--- Suggested BPF Filters for `{}` ---", interface_name);
    for (i, (desc, bpf)) in filters.iter().enumerate() {
        if bpf.is_empty() {
            println!("  [{}] {} (no filter)", i, desc);
        } else {
            println!("  [{}] {}", i, desc);
        }
    }
    println!("  [c] Custom filter");
    println!("  [Enter] to skip, or 'q' to quit\n");

    loop {
        print!("Select a filter by number, 'c' for custom, Enter to skip, or 'q' to quit: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            eprintln!("Failed to read input");
            continue;
        }

        let trimmed = input.trim();

        if trimmed.eq_ignore_ascii_case("q") {
            println!("Quitting");
            std::process::exit(0);
        }

        if trimmed.is_empty() {
            return None;
        }

        if trimmed.eq_ignore_ascii_case("c") {
            print!("Enter custom BPF filter: ");
            io::stdout().flush().unwrap();

            let mut custom = String::new();
            if io::stdin().read_line(&mut custom).is_err() {
                eprintln!("Failed to read input");
                continue;
            }

            let custom_trimmed = custom.trim();
            if custom_trimmed.is_empty() {
                return None;
            } else {
                return Some(custom_trimmed.to_string());
            }
        }

        if let Ok(index) = trimmed.parse::<usize>() {
            if index < filters.len() {
                let bpf = filters[index].1;
                return if bpf.is_empty() { None } else { Some(bpf.to_string()) };
            }
        }

        eprintln!("Invalid selection. Please try again.");
    }
} // prompt_for_bpf_filter
