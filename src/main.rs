mod capture;
mod core;
mod packet;
mod ui;

use crate::core::capture_loop::initialize_capture;
use crate::core::signal::setup_ctrlc_handler;
use crate::core::summary::print_packet_summary;
use crate::packet::{parse_and_print_packet, PacketType};

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::{thread, time, process};
use pcap;

fn main() {
    // Setup the atomic running flag for shutdown
    let running = Arc::new(AtomicBool::new(true));
    setup_ctrlc_handler(Arc::clone(&running));

    // Initialize capture session
    let mut cap = match initialize_capture() {
        Ok(c) => c,
        Err(err) => {
            eprintln!("{}", err);
            return;
        }
    };

    // Shared state for packet counts
    let packet_counts = Arc::new(Mutex::new(HashMap::<PacketType, usize>::new()));

    // Capture loop: runs while running flag is true
    while running.load(Ordering::SeqCst) {
    match cap.next_packet() {
        Ok(packet) => {
            match parse_and_print_packet(&packet.data) {
                Ok(ptype) => {
                    let mut counts = packet_counts.lock().unwrap();
                    *counts.entry(ptype).or_insert(0) += 1;
                }
                Err(err) => eprintln!("Error parsing packet: {}", err),
            }
        }
        Err(pcap::Error::TimeoutExpired) => {
            // No packet available yet, just continue looping
            thread::sleep(time::Duration::from_millis(10));
        }
        Err(err) => {
            eprintln!("Error reading packet: {}", err);
            thread::sleep(time::Duration::from_millis(10));
        }
    } // match
} // while

    // After Ctrl+C triggered, print summary and exit
    print_packet_summary(Arc::clone(&packet_counts));

    process::exit(0);
}
