use eframe::egui;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::Instant;
use std::collections::HashMap;

use crate::core::runner::run_packet_loop;
use crate::core::signal::setup_ctrlc_handler;
use crate::core::capture_loop::{reinitialize_capture, get_available_devices};
use crate::packet::{PacketInfo, PacketType};

pub struct SniffyApp {
    started_at: Instant,
    running: Arc<AtomicBool>,
    packet_rx: Receiver<PacketInfo>,
    packet_counts: Arc<Mutex<HashMap<PacketType, usize>>>,
    log: Arc<Mutex<Vec<String>>>,

    // New state
    available_interfaces: Vec<String>,
    selected_interface: Option<String>,
    bpf_filter: String,
    save_pcap: bool,
    pcap_filename: String,
    capture_started: bool,
}

impl SniffyApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let started_at = Instant::now();
        let running = Arc::new(AtomicBool::new(true));
        let packet_counts = Arc::new(Mutex::new(HashMap::new()));
        let log = Arc::new(Mutex::new(Vec::new()));

        setup_ctrlc_handler(Arc::clone(&running));

        let (tx, rx): (Sender<PacketInfo>, Receiver<PacketInfo>) = mpsc::channel();

        // Load interfaces at startup
        let available_interfaces = match get_available_devices() {
            Ok(devs) => devs.into_iter().map(|d| d.name).collect(),
            Err(e) => {
                eprintln!("❌ Failed to list interfaces: {e}");
                vec![]
            }
        };

        SniffyApp {
            started_at,
            running,
            packet_rx: rx,
            packet_counts,
            log,

            available_interfaces,
            selected_interface: None,
            bpf_filter: String::new(),
            save_pcap: false,
            pcap_filename: "capture.pcap".to_string(),
            capture_started: false,
        }
    }

    fn start_capture(&mut self) {
        if self.capture_started {
            return;
        }

        let device_name = match self.selected_interface.clone() {
            Some(name) => name,
            None => {
                eprintln!("⚠️ No interface selected");
                return;
            }
        };

        let bpf_filter = self.bpf_filter.clone();
        let running = Arc::clone(&self.running);
        let packet_counts = Arc::clone(&self.packet_counts);
        let log = Arc::clone(&self.log);
        let (tx, _rx) = mpsc::channel::<PacketInfo>();
        self.packet_rx = _rx;

        thread::spawn(move || {
            let cap = match reinitialize_capture(&device_name) {
                Ok(c) => Arc::new(Mutex::new(c)),
                Err(e) => {
                    eprintln!("Failed to start capture: {e}");
                    return;
                }
            };

            // Apply BPF filter
            {
                let mut cap_guard = cap.lock().unwrap();
                if let Err(e) = crate::core::capture_loop::apply_bpf_filter(&mut cap_guard, &bpf_filter) {
                    eprintln!("Error applying BPF filter: {e}");
                }
            }

            let savefile = None; // TODO: wire this in
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

        self.capture_started = true;
    }
}

impl eframe::App for SniffyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Handle incoming packets
        while let Ok(packet) = self.packet_rx.try_recv() {
            let mut log = self.log.lock().unwrap();
            let line = format!(
                "[{} -> {}] {:?}",
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
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            // Interface Selector
            ui.horizontal(|ui| {
                ui.label("Interface:");
                egui::ComboBox::from_id_source("interface_combo")
                    .selected_text(
                        self.selected_interface
                            .as_deref()
                            .unwrap_or("<select>"),
                    )
                    .show_ui(ui, |cb| {
                        for iface in &self.available_interfaces {
                            cb.selectable_value(
                                &mut self.selected_interface,
                                Some(iface.clone()),
                                iface,
                            );
                        }
                    });
            });

            // BPF filter input
            ui.horizontal(|ui| {
                ui.label("Filter:");
                ui.text_edit_singleline(&mut self.bpf_filter);
            });

            // Start button
            if ui.button("Start Capture").clicked() {
                self.start_capture();
            }

            ui.separator();

            // Protocol counts
            ui.horizontal(|ui| {
                ui.label("Captured Protocols:");
                if let Ok(counts) = self.packet_counts.lock() {
                    for (ptype, count) in counts.iter() {
                        ui.label(format!("{}: {}", ptype, count));
                    }
                }
            });

            ui.separator();

            // Log viewer
            ui.label("Live Packet Log:");
            egui::ScrollArea::vertical().max_height(400.0).show(ui, |ui| {
                if let Ok(log) = self.log.lock() {
                    for line in log.iter().rev().take(100) {
                        ui.label(line);
                    }
                }
            });
        });

        ctx.request_repaint();
    }
}
