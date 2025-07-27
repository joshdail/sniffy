use eframe::egui;
use std::{
    collections::HashMap,
    sync::{
        atomic::AtomicBool,
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread,
};

use crate::core::capture_loop::{get_available_devices, reinitialize_capture, apply_bpf_filter};
use crate::core::runner::run_packet_loop;
use crate::core::signal::setup_ctrlc_handler;
use crate::packet::{PacketInfo, PacketType};

/// Represents the kind of interface detected for BPF filtering suggestions.
enum InterfaceKind {
    Loopback,
    Ethernet,
    Unknown,
}

fn detect_interface_type(name: &str) -> InterfaceKind {
    if name.contains("lo") {
        InterfaceKind::Loopback
    } else if name.contains("en") || name.contains("eth") {
        InterfaceKind::Ethernet
    } else {
        InterfaceKind::Unknown
    }
}

fn suggested_filters(interface: &str) -> Vec<String> {
    match detect_interface_type(interface) {
        InterfaceKind::Loopback => vec![
            "tcp".into(),
            "udp".into(),
            "port 53".into(),
            "ip".into(),
            "icmp".into(),
        ],
        InterfaceKind::Ethernet => vec![
            "tcp".into(),
            "udp".into(),
            "port 80".into(),
            "port 443".into(),
            "port 53".into(),
            "ip".into(),
            "icmp".into(),
        ],
        InterfaceKind::Unknown => vec!["ip".into(), "tcp".into()],
    }
}

/// The main GUI app for Sniffy
pub struct SniffyApp {
    running: Arc<AtomicBool>,
    packet_rx: Receiver<PacketInfo>,
    packet_tx: Sender<PacketInfo>,
    packet_counts: Arc<Mutex<HashMap<PacketType, usize>>>,
    log: Arc<Mutex<Vec<String>>>,
    selected_interface: Option<String>,
    available_interfaces: Vec<String>,
    selected_filter: Option<String>,
    save_pcap: bool,
    pcap_filename: String,
    capture_started: bool,
}

impl SniffyApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let packet_counts = Arc::new(Mutex::new(HashMap::new()));
        let log = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = mpsc::channel();

        setup_ctrlc_handler(running.clone());

       let available_interfaces = get_available_devices()
            .map(|list| list.into_iter().map(|d| d.name).collect())
            .unwrap_or_else(|e| {
                eprintln!("Failed to load interfaces: {e}");
                vec![]
            });


        SniffyApp {
            running,
            packet_rx: rx,
            packet_tx: tx,
            packet_counts,
            log,
            selected_interface: None,
            selected_filter: None,
            save_pcap: false,
            pcap_filename: "capture.pcap".into(),
            available_interfaces,
            capture_started: false,
        }
    }

    fn start_capture(&mut self) {
        if self.capture_started {
            return;
        }

        let Some(device_name) = self.selected_interface.clone() else {
            eprintln!("No interface selected.");
            return;
        };

        let bpf_filter = self.selected_filter.clone().unwrap_or_default();
        let running = self.running.clone();
        let packet_counts = self.packet_counts.clone();
        let log = self.log.clone();
        let tx = self.packet_tx.clone();

        thread::spawn(move || {
            let cap = match reinitialize_capture(&device_name) {
                Ok(c) => Arc::new(Mutex::new(c)),
                Err(e) => {
                    eprintln!("Failed to start capture: {e}");
                    return;
                }
            };

            {
                let mut cap_guard = cap.lock().unwrap();
                if let Err(e) = apply_bpf_filter(&mut cap_guard, &bpf_filter) {
                    eprintln!("Error applying BPF filter: {e}");
                }
            }

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

        self.capture_started = true;
    }
}

impl eframe::App for SniffyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(packet) = self.packet_rx.try_recv() {
            if let Ok(mut log) = self.log.lock() {
                let line = format!(
                    "[{} -> {}] {:?}",
                    packet.src_ip.unwrap_or_else(|| "??".into()),
                    packet.dst_ip.unwrap_or_else(|| "??".into()),
                    packet.packet_type
                );
                log.push(line);
            }

            if let Ok(mut counts) = self.packet_counts.lock() {
                *counts.entry(packet.packet_type.clone()).or_insert(0) += 1;
            }
        }

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.heading("Sniffy - GUI Packet Sniffer");

            ui.horizontal(|ui| {
                ui.label("Interface:");
                egui::ComboBox::from_id_salt("interface_combo")
                    .selected_text(
                        self.selected_interface
                            .as_ref()
                            .map(|s| s.as_str())
                            .unwrap_or("Select interface"),
                    )
                    .show_ui(ui, |ui| {
                        for iface in &self.available_interfaces {
                            ui.selectable_value(
                                &mut self.selected_interface,
                                Some(iface.clone()),
                                iface,
                            );
                        }
                    });
            });

            if let Some(iface) = &self.selected_interface {
                let filters = suggested_filters(iface);
                ui.horizontal(|ui| {
                    ui.label("BPF Filter:");
                    egui::ComboBox::from_id_salt("bpf_filter_combo")
                        .selected_text(
                            self.selected_filter
                                .as_deref()
                                .unwrap_or("Select filter"),
                        )
                        .show_ui(ui, |ui| {
                            for f in &filters {
                                ui.selectable_value(
                                    &mut self.selected_filter,
                                    Some(f.clone()),
                                    f,
                                );
                            }
                        });
                });
            }

            ui.horizontal(|ui| {
                ui.checkbox(&mut self.save_pcap, "Save to PCAP?");
                if self.save_pcap {
                    ui.text_edit_singleline(&mut self.pcap_filename);
                }
            });

            if ui.button("Start Capture").clicked() {
                self.start_capture();
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

        ctx.request_repaint(); // Smooth refresh
    }
}
