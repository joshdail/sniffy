use eframe::egui;
use std::sync::{Arc, Mutex};
use crate::packet::{PacketInfo, PacketType};

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

    match pkt.packet_type {
        PacketType::DNS => {
            let queries = pkt.dns_queries
                .as_ref()
                .map(|q| q.join(", "))
                .unwrap_or_else(|| "<no queries>".into());
            format!("[{} -> {}] DNS Query: {}", src, dst, queries)
        }
        PacketType::TCP => {
            let src_port = pkt.src_port.map_or("?".into(), |p| p.to_string());
            let dst_port = pkt.dst_port.map_or("?".into(), |p| p.to_string());
            let flags = pkt.tcp_flags.map_or("".into(), |f| format!(" ({})", f));
            format!("[{}:{} -> {}:{}] TCP{}", src, src_port, dst, dst_port, flags)
        }
        PacketType::UDP => {
            let src_port = pkt.src_port.map_or("?".into(), |p| p.to_string());
            let dst_port = pkt.dst_port.map_or("?".into(), |p| p.to_string());
            format!("[{}:{} -> {}:{}] UDP", src, src_port, dst, dst_port)
        }
        _ => {
            format!("[{} -> {}] {}", src, dst, pkt.packet_type)
        }
    }
}
