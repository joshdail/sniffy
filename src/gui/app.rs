use eframe::egui;
use std::{
    collections::HashMap,
    sync::{
        atomic::AtomicBool,
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
};

use crate::core::capture_loop::{get_available_devices, reinitialize_capture, apply_bpf_filter};
use crate::core::runner::{setup_savefile, run_packet_loop};
use crate::core::signal::setup_ctrlc_handler;
use crate::packet::{PacketInfo, PacketType};
use crate::gui::components::{
    interface_selector::interface_selector,
    filter_input::filter_input,
    stats_panel::stats_panel,
    packet_log::packet_log,
    gui_state::*
};

/// The main GUI app for Sniffy
pub struct SniffyApp {
    running: Arc<AtomicBool>,
    packet_rx: Receiver<PacketInfo>,
    packet_tx: Sender<PacketInfo>,
    packet_counts: Arc<Mutex<HashMap<PacketType, usize>>>,
    log: Arc<Mutex<Vec<PacketInfo>>>,
    selected_interface: Option<String>,
    available_interfaces: Vec<String>,
    selected_filter: Option<String>,
    save_pcap: bool,
    pcap_filename: String,
    capture_state: CaptureState,
    capture_thread_handle: Option<JoinHandle<()>>
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
            capture_state: CaptureState::Idle,
            capture_thread_handle: None
        }
    }

    fn start_capture(&mut self) {
        if self.capture_state == CaptureState::Capturing {
            return;
        }

        let Some(device_name) = self.selected_interface.clone() else {
            eprintln!("No interface selected.");
            return;
        };

        let bpf_filter = self.selected_filter.clone().unwrap_or_default();

        // Set running = true, in case it was false after a stop
        self.running.store(true, std::sync::atomic::Ordering::SeqCst);

        let running = self.running.clone();
        let packet_counts = self.packet_counts.clone();
        // let log = self.log.clone();
        let tx = self.packet_tx.clone();

        let savefile_name = if self.save_pcap {
            rfd::FileDialog::new()
                .add_filter("PCAP file ", &["pcap"])
                .set_file_name(&self.pcap_filename)
                .save_file()
                .map(|path| path.to_string_lossy().to_string())
        } else {
            None
        };

        let handle = thread::spawn(move || {
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

            let savefile = savefile_name.and_then(|filename| {
                setup_savefile(&cap, &filename)
            });
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

        self.capture_thread_handle = Some(handle);
        self.capture_state = CaptureState::Capturing;
    } // start_capture

    fn stop_capture(&mut self) {
        if self.capture_state != CaptureState::Capturing {
            return;
        }

        self.running.store(false, std::sync::atomic::Ordering::SeqCst);

        if let Some(handle) = self.capture_thread_handle.take() {
            if let Err(e) = handle.join() {
                eprintln!("Failed to join capture thread: {:?}", e);
            }
        }

        self.capture_state = CaptureState::Idle;
    } // stop_capture

} // impl SniffyApp

impl eframe::App for SniffyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(packet) = self.packet_rx.try_recv() {
            if let Ok(mut log) = self.log.lock() {
                log.push(packet.clone());
            }

            if let Ok(mut counts) = self.packet_counts.lock() {
                *counts.entry(packet.packet_type.clone()).or_insert(0) += 1;
            }
        }

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.heading("Sniffy - GUI Packet Sniffer");

            interface_selector(ui, &self.available_interfaces, &mut self.selected_interface);

            if let Some(iface) = &self.selected_interface {
                let filters = suggested_filters(iface);
                filter_input(ui, &filters, &mut self.selected_filter);
            }

            ui.horizontal(|ui| {
                ui.checkbox(&mut self.save_pcap, "Save to PCAP?");
                if self.save_pcap {
                    ui.text_edit_singleline(&mut self.pcap_filename);
                }
            });

            if self.capture_state == CaptureState::Idle {
            if ui.button("Start Capture").clicked() {
                self.start_capture();
                }
            } else {
                if ui.button("Stop Capture").clicked() {
                    self.stop_capture();
                }
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            stats_panel(ui, &self.packet_counts);
            ui.separator();
            packet_log(ui, &self.log);
        });

        ctx.request_repaint();
    }
}
