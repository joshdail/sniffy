use eframe::egui;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::Instant;

use crate::core::runner::{run_packet_loop, setup_savefile};
use crate::core::signal::setup_ctrlc_handler;
use crate::packet::{PacketInfo, PacketType};
use crate::core::capture_loop::{reinitialize_capture, get_available_devices};

use std::collections::HashMap;

/// The main GUI app for Sniffy
pub struct SniffyApp {
    started_at: Instant,
    running: Arc<AtomicBool>,
    packet_rx: Receiver<PacketInfo>,
    packet_counts: Arc<Mutex<HashMap<PacketType, usize>>>,
    log: Arc<Mutex<Vec<String>>>,

    // New GUI state:
    available_interfaces: Vec<String>,
    selected_interface: Option<String>,
    bpf_filter: String,
    save_pcap: bool,
    pcap_filename: String,

    // Capture thread handle and channel sender for control:
    capture_thread_handle: Option<thread::JoinHandle<()>>,
    packet_tx: Option<Sender<PacketInfo>>,
}

impl SniffyApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Load a better Unicode font for logs
        let mut fonts = egui::FontDefinitions::default();
        fonts.font_data.insert(
            "NotoSans".to_owned(),
            egui::FontData::from_static(include_bytes!("../../fonts/NotoSans-Regular.ttf")).into(),
        );
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .insert(0, "NotoSans".to_owned());
        cc.egui_ctx.set_fonts(fonts);

        let started_at = Instant::now();
        let running = Arc::new(AtomicBool::new(true));
        setup_ctrlc_handler(Arc::clone(&running));

        // Get available devices early
        let available_interfaces = get_available_devices()
            .unwrap_or_default()
            .into_iter()
            .map(|d| d.name)
            .collect::<Vec<_>>();

        // Pick first interface if any
        let selected_interface = available_interfaces.get(0).cloned();

        let (packet_tx, packet_rx) = mpsc::channel();

        // Shared state
        let packet_counts = Arc::new(Mutex::new(HashMap::new()));
        let log = Arc::new(Mutex::new(Vec::new()));

        // Start capture thread if interface is available
        let capture_thread_handle = selected_interface.as_ref().map(|iface| {
            Self::spawn_capture_thread(
                iface.clone(),
                "".to_string(),
                false,
                "capture.pcap".to_string(),
                Arc::clone(&running),
                Arc::clone(&packet_counts),
                Arc::clone(&log),
                packet_tx.clone(),
            )
        });

        Self {
            started_at,
            running,
            packet_rx,
            packet_counts,
            log,
            available_interfaces,
            selected_interface,
            bpf_filter: "".to_string(),
            save_pcap: false,
            pcap_filename: "capture.pcap".to_string(),
            capture_thread_handle,
            packet_tx: Some(packet_tx),
        }
    }

    fn spawn_capture_thread(
        device_name: String,
        bpf_filter: String,
        save_pcap: bool,
        pcap_filename: String,
        running: Arc<AtomicBool>,
        packet_counts: Arc<Mutex<HashMap<PacketType, usize>>>,
        log: Arc<Mutex<Vec<String>>>,
        packet_tx: Sender<PacketInfo>,
    ) -> thread::JoinHandle<()> {
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
                if !bpf_filter.is_empty() {
                    if let Err(e) = crate::core::capture_loop::apply_bpf_filter(&mut cap_guard, &bpf_filter) {
                        eprintln!("Error applying BPF filter: {e}");
                    }
                }
            }

            // Setup savefile if needed
            let savefile = if save_pcap {
                setup_savefile_from_filename(&cap, &pcap_filename)
            } else {
                None
            };

            let debug = false;

            if let Err(e) = run_packet_loop(
                running,
                cap,
                savefile,
                packet_counts,
                debug,
                Some(packet_tx),
            ) {
                eprintln!("Packet loop error: {e}");
            }
        })
    }

    fn restart_capture_thread(&mut self) {
        // Stop old thread
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.capture_thread_handle.take() {
            let _ = handle.join();
        }

        // Reset running flag and channel
        self.running = Arc::new(AtomicBool::new(true));
        let (tx, rx) = mpsc::channel();
        self.packet_rx = rx;
        self.packet_tx = Some(tx.clone());

        self.packet_counts = Arc::new(Mutex::new(HashMap::new()));
        self.log = Arc::new(Mutex::new(Vec::new()));

        if let Some(ref iface) = self.selected_interface {
            self.capture_thread_handle = Some(Self::spawn_capture_thread(
                iface.clone(),
                self.bpf_filter.clone(),
                self.save_pcap,
                self.pcap_filename.clone(),
                Arc::clone(&self.running),
                Arc::clone(&self.packet_counts),
                Arc::clone(&self.log),
                tx,
            ));
        }
    }
}

fn setup_savefile_from_filename(
    cap: &Arc<Mutex<pcap::Capture<pcap::Active>>>,
    filename: &str,
) -> Option<pcap::Savefile> {
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
}

impl eframe::App for SniffyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Pull packets from channel and update log
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
            // Timer removed as requested
        });

        egui::SidePanel::left("left_panel").show(ctx, |ui| {
            ui.heading("Settings");

            // Interface selector
            ui.label("Network Interface:");
            egui::ComboBox::from_id_salt("interface_combo")
                .selected_text(self.selected_interface.clone().unwrap_or_else(|| "None".to_string()))
                .show_ui(ui, |ui| {
                    for iface in &self.available_interfaces {
                        ui.selectable_value(&mut self.selected_interface, Some(iface.clone()), iface);
                    }
                });

            // BPF filter input
            ui.label("BPF Filter:");
            let filter_changed = ui.text_edit_singleline(&mut self.bpf_filter).changed();

            // PCAP save options
            ui.checkbox(&mut self.save_pcap, "Save capture to PCAP file");
            if self.save_pcap {
                ui.label("PCAP Filename:");
                ui.text_edit_singleline(&mut self.pcap_filename);
            }

            // Apply filter and restart capture button
            if ui.button("Apply & Restart Capture").clicked() || filter_changed {
                self.restart_capture_thread();
            }
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
