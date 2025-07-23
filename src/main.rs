mod capture;
mod core;
mod packet;
mod ui;

extern crate lazy_static;

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

    // Initialize terminal UI mode (raw + alt screen)
    if let Err(e) = initialize_tui() {
        eprintln!("Failed to initialize TUI: {}", e);
        return;
    }

    // Spawn input handler thread to listen for 'q' key
    spawn_input_handler(Arc::clone(&running));
    // Spawn UI drawing thread
    start_ui_thread(Arc::clone(&running));

    // Track packet counts
    let packet_counts = Arc::new(Mutex::new(HashMap::<PacketType, usize>::new()));

    // Main packet capture loop
    while running.load(Ordering::SeqCst) {
        match cap.next_packet() {
            Ok(packet) => match parse_packet(&packet.data) {
                Ok(info) => {
                    display_packet_info(&info);

                    let mut counts = packet_counts.lock().unwrap();
                    *counts.entry(info.packet_type.clone()).or_insert(0) += 1;
                }
                Err(e) => eprintln!("Parse error: {}", e),
            },
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
