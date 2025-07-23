mod capture;
mod core;
mod packet;
mod ui;
mod cli;

extern crate lazy_static;

use clap::Parser;
use std::io::{self, Write};

use crate::cli::CliArgs;
use crate::core::capture_loop::initialize_capture;
use crate::core::signal::setup_ctrlc_handler;
use crate::packet::{parse_packet, PacketType};
use crate::ui::tui::{initialize_tui, display_packet_info, print_final_summary, spawn_input_handler, start_ui_thread};

use pcap;
use std::{
    collections::HashMap,
    process,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time,
};

fn main() {
    // Parse CLI args
    let args = CliArgs::parse();

    // Shared shutdown flag
    let running = Arc::new(AtomicBool::new(true));
    setup_ctrlc_handler(Arc::clone(&running));

    // Open pcap capture session
    let mut cap = match initialize_capture() {
        Ok(c) => c,
        Err(err) => {
            eprintln!("Error initializing capture: {}", err);
            return;
        }
    };

    // Determine export option
    let export_enabled = if let Some(file) = args.export.clone() {
        !file.is_empty()
    } else {
        // Prompt user
        print!("Do you want to export the capture to a PCAP file? (y/N): ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
    };

    // Setup PCAP savefile if enabled
    let mut savefile = if export_enabled {
        let filename = if let Some(file) = args.export.clone() {
            if file.is_empty() {
                "capture.pcap".to_string()
            } else {
                file
            }
        } else {
            "capture.pcap".to_string()
        };

        match cap.savefile(&filename) {
            Ok(sf) => {
                println!("Exporting packets to {}", filename);
                Some(sf)
            }
            Err(e) => {
                eprintln!("Failed to create savefile {}: {}", filename, e);
                None
            }
        }
    } else {
        None
    };

    // Initialize terminal UI mode (raw + alt screen)
    if let Err(e) = initialize_tui() {
        eprintln!("Failed to initialize TUI: {}", e);
        return;
    }

    // Track packet counts
    let packet_counts = Arc::new(Mutex::new(HashMap::<PacketType, usize>::new()));

    // Spawn input handler thread to listen for 'q' key
    spawn_input_handler(Arc::clone(&running));
    // Spawn UI drawing thread
    start_ui_thread(Arc::clone(&running), Arc::clone(&packet_counts));

    // Main packet capture loop
    while running.load(Ordering::SeqCst) {
        match cap.next_packet() {
            Ok(packet) => {
                match parse_packet(&packet.data) {
                    Ok(info) => {
                        display_packet_info(&info);

                        let mut counts = packet_counts.lock().unwrap();
                        *counts.entry(info.packet_type.clone()).or_insert(0) += 1;
                    }
                    Err(e) => eprintln!("Parse error: {}", e),
                }

                // Write packet to savefile if enabled
                if let Some(sf) = &mut savefile {
                    sf.write(&packet);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                thread::sleep(time::Duration::from_millis(10));
            }
            Err(e) => {
                eprintln!("Capture error: {}", e);
                thread::sleep(time::Duration::from_millis(10));
            }
        }
    }

    // Clean up and print summary (UI thread already cleaned terminal)
    print_final_summary(packet_counts);

    process::exit(0);
}
