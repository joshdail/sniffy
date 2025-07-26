use std::{
    collections::HashMap,
    io::{self, Write},
    sync::{
        atomic::Ordering,
        mpsc::Sender,
        Arc, Mutex,
    },
    thread,
    time,
};

use clap::Error;
use pcap;
use crate::cli::CliArgs;
use crate::packet::{parse_packet, PacketType, PacketInfo};

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
    tx_gui: Option<Sender<PacketInfo>>,
) -> Result<(), Error> {
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
                    if let Some(gui_sender) = &tx_gui {
                        let _ = gui_sender.send(info.clone());
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

    Ok(())
}

fn prompt_yes_no(message: &str) -> bool {
    print!("{message} ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}
