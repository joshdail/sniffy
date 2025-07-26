use eframe::egui;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::Instant;

use crate::core::runner::run_packet_loop;
use crate::core::signal::setup_ctrlc_handler;
use crate::packet::{PacketInfo, PacketType};
use crate::core::capture_loop::reinitialize_capture;

use std::collections::HashMap;

/// The main GUI app for Sniffy
pub struct SniffyApp {
    started_at: Instant,
    running: Arc<AtomicBool>,
    packet_rx: Receiver<PacketInfo>,
    packet_counts: Arc<Mutex<HashMap<PacketType, usize>>>,
    log: Arc<Mutex<Vec<String>>>,
}

impl SniffyApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let started_at = Instant::now();
        let running = Arc::new(AtomicBool::new(true));
        let packet_counts = Arc::new(Mutex::new(HashMap::new()));
        let log = Arc::new(Mutex::new(Vec::new()));

        setup_ctrlc_handler(Arc::clone(&running));

        let (tx, rx): (Sender<PacketInfo>, Receiver<PacketInfo>) = mpsc::channel();

        // TODO: Replace with user-selected interface via GUI
        let device_name = "en0";
        let bpf_filter = String::new();

        {
            let running = Arc::clone(&running);
            let packet_counts = Arc::clone(&packet_counts);
            let log = Arc::clone(&log);
            let tx = tx.clone();
            let device_name = device_name.to_string();
            let bpf_filter = bpf_filter.clone();

            thread::spawn(move || {
                let cap = match reinitialize_capture(&device_name) {
                    Ok(c) => Arc::new(Mutex::new(c)),
                    Err(e) => {
                        eprintln!("Failed to start capture: {e}");
                        return;
                    }
                };

                // Apply the BPF filter before starting the loop
                {
                    let mut cap_guard = cap.lock().unwrap();
                    if let Err(e) = crate::core::capture_loop::apply_bpf_filter(&mut cap_guard, &bpf_filter) {
                        eprintln!("Error applying BPF filter: {e}");
                    }
                } // lock dropped here

                let savefile = None;
                let debug = false;

                if let Err(e) = run_packet_loop(
                    running,
                    cap,
                    savefile,
                    packet_counts,
                    debug,
                    Some(tx),
                ) {
                    eprintln!("Packet loop error: {e}");
                }
            });
        }

        SniffyApp {
            started_at,
            running,
            packet_rx: rx,
            packet_counts,
            log,
        }
    }
}

impl eframe::App for SniffyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Pull packets from channel and update log
        while let Ok(packet) = self.packet_rx.try_recv() {
            let mut log = self.log.lock().unwrap();
            let line = format!(
                "[{} → {}] {:?}",
                packet.src_ip.unwrap_or_else(|| "??".into()),
                packet.dst_ip.unwrap_or_else(|| "??".into()),
                packet.packet_type
            );
            log.push(line);

            if let Ok(mut counts) = self.packet_counts.lock() {
                *counts.entry(packet.packet_type.clone()).or_insert(0) += 1;
            }
        }

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.heading("Sniffy - GUI Packet Sniffer");
            ui.label(format!("Running for: {:.2?}", self.started_at.elapsed()));
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Captured Protocols:");
                if let Ok(counts) = self.packet_counts.lock() {
                    for (ptype, count) in counts.iter() {
                        ui.label(format!("{}: {}", ptype, count));
                    }
                }
            });

            ui.separator();
            ui.label("Live Packet Log:");
            egui::ScrollArea::vertical().max_height(400.0).show(ui, |ui| {
                if let Ok(log) = self.log.lock() {
                    for line in log.iter().rev().take(100) {
                        ui.label(line);
                    }
                }
            });
        });

        ctx.request_repaint(); // Ensure GUI refresh
    }
}
