use eframe::egui;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::packet::PacketType;

pub fn stats_panel(
    ui: &mut egui::Ui,
    packet_counts: &Arc<Mutex<HashMap<PacketType, usize>>>,
) {
    ui.horizontal(|ui| {
        ui.label("Captured Protocols:");
        if let Ok(counts) = packet_counts.lock() {
            for (ptype, count) in counts.iter() {
                ui.label(format!("{}: {}", ptype, count));
            }
        }
    });
}
