use std::{
    collections::HashMap,
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
use crate::packet::{parse_packet, PacketType, PacketInfo};

pub fn setup_savefile(
    cap: &Arc<Mutex<pcap::Capture<pcap::Active>>>,
    filename: &str,
) -> Option<pcap::Savefile> {
    if filename.trim().is_empty() {
        return None;
    }

    match cap.lock() {
        Ok(cap_guard) => match cap_guard.savefile(filename) {
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
} // setup_savefile

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