use std::{
    collections::HashMap,
    io::{self, Write},
    sync::{
        atomic::Ordering,
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread,
    time,
};

use clap::Error;
use pcap;
use crate::cli::CliArgs;
use crate::packet::{parse_packet, PacketType, PacketInfo};
use crate::ui::tui::log::{display_packet_info, print_final_summary};

/// Runs a separate thread that receives parsed packet info from a channel
/// and prints/logs the info, throttling output to avoid flooding terminal/UI.
fn start_packet_display_thread(rx: Receiver<PacketInfo>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while let Ok(packet_info) = rx.recv() {
            display_packet_info(&packet_info);
        }
    })
}

pub fn setup_savefile(
    args: &CliArgs,
    cap: &Arc<Mutex<pcap::Capture<pcap::Active>>>,
) -> Option<pcap::Savefile> {
    let export_enabled = if let Some(file) = args.export.as_ref() {
        !file.is_empty()
    } else {
        prompt_yes_no("Do you want to export the capture to a PCAP file? (y/N):")
    };

    if !export_enabled {
        return None;
    }

    let filename = args
        .export
        .as_ref()
        .filter(|f| !f.is_empty())
        .cloned()
        .unwrap_or_else(|| "capture.pcap".to_string());

    match cap.lock() {
        Ok(cap_guard) => match cap_guard.savefile(&filename) {
            Ok(sf) => {
                println!("Exporting packets to {}", filename);
                Some(sf)
            }
            Err(e) => {
                eprintln!("Failed to create savefile {}: {}", filename, e);
                None
            }
        },
        Err(e) => {
            eprintln!("Failed to lock capture mutex: {}", e);
            None
        }
    }
}

pub fn run_packet_loop(
    running: Arc<std::sync::atomic::AtomicBool>,
    cap: Arc<Mutex<pcap::Capture<pcap::Active>>>,
    mut savefile: Option<pcap::Savefile>,
    packet_counts: Arc<Mutex<HashMap<PacketType, usize>>>,
    debug_enabled: bool,
) -> Result<(), Error> {
    // Channel for sending parsed packet info to display thread
    let (tx, rx): (Sender<PacketInfo>, Receiver<PacketInfo>) = mpsc::channel();

    // Spawn the display thread only if debug is enabled
    let display_handle = if debug_enabled {
        Some(start_packet_display_thread(rx))
    } else {
        None
    };

    while running.load(Ordering::SeqCst) {
        let packet_data = {
            let mut guard = match cap.lock() {
                Ok(g) => g,
                Err(poisoned) => {
                    eprintln!("⚠️ Failed to lock capture mutex (poisoned): {}", poisoned);
                    thread::sleep(time::Duration::from_millis(100));
                    continue;
                }
            };

            match guard.next_packet() {
                Ok(packet) => {
                    if let Some(sf) = &mut savefile {
                        sf.write(&packet);
                    }
                    Some(packet.data.to_vec())
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Yield instead of sleep for better responsiveness
                    thread::yield_now();
                    None
                }
                Err(e) => {
                    eprintln!("Capture error: {}", e);
                    thread::sleep(time::Duration::from_millis(10));
                    None
                }
            }
        };

        if let Some(data) = packet_data {
            match parse_packet(&data) {
                Ok(info) => {
                    if debug_enabled {
                        // Send parsed packet info to display thread
                        if let Err(e) = tx.send(info.clone()) {
                            eprintln!("Packet display thread has stopped: {}", e);
                        }
                    }
                    if let Ok(mut counts) = packet_counts.lock() {
                        *counts.entry(info.packet_type.clone()).or_insert(0) += 1;
                    } else {
                        eprintln!("⚠️ Failed to lock packet counts mutex");
                    }
                }
                Err(e) => {
                    eprintln!("Parse error: {}", e);
                }
            }
        }
    }

    // Close the sender so display thread will exit
    drop(tx);

    if let Some(handle) = display_handle {
        if let Err(e) = handle.join() {
            eprintln!("Packet display thread panicked: {:?}", e);
        }
    }

    print_final_summary(packet_counts);
    Ok(())
}

fn prompt_yes_no(message: &str) -> bool {
    print!("{message} ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}
