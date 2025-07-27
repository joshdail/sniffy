use eframe::egui;
use std::sync::{Arc, Mutex};

use crate::packet::PacketInfo;

pub fn packet_log(ui: &mut egui::Ui, log: &Arc<Mutex<Vec<PacketInfo>>>) {
    ui.label("Live Packet Log:");
    egui::ScrollArea::vertical().max_height(400.0).show(ui, |ui| {
        if let Ok(log) = log.lock() {
            for pkt in log.iter().rev().take(100) {
                let line = format_packet_line(pkt);
                ui.label(line);
            }
        }
    });
}

fn format_packet_line(pkt: &PacketInfo) -> String {
    let src = pkt.src_ip.clone().unwrap_or_else(|| "??".into());
    let dst = pkt.dst_ip.clone().unwrap_or_else(|| "??".into());

    if let Some(queries) = &pkt.dns_queries {
        return format!("[{} -> {}] DNS Query: {}", src, dst, queries.join(", "));
    }

    if pkt.packet_type.to_string() == "TCP" {
        if let Some(flags) = pkt.tcp_flags {
            return format!("[{} -> {}] TCP {} → {} ({})",
                src,
                dst,
                pkt.src_port.map_or("?".into(), |p| p.to_string()),
                pkt.dst_port.map_or("?".into(), |p| p.to_string()),
                flags,
            );
        }
    }

    format!("[{} -> {}] {}", src, dst, pkt.packet_type)
}
