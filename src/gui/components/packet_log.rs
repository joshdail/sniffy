use eframe::egui::{RichText, Ui};
use std::sync::{Arc, Mutex};
use crate::packet::{PacketInfo, PacketType};
use crate::gui::components::gui_state::ProtocolDisplay;

/// Format a packet line (you can extend this with more info)
fn format_packet_line_with_label(packet: &PacketInfo) -> String {
    // For example, print src -> dst, ports, and protocol
    let src = packet.src_ip.as_deref().unwrap_or("-");
    let dst = packet.dst_ip.as_deref().unwrap_or("-");
    let sport = packet.src_port.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
    let dport = packet.dst_port.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
    format!("{}:{} -> {}:{} [{:?}]", src, sport, dst, dport, packet.packet_type)
}

pub fn packet_log(ui: &mut Ui, log: &Arc<Mutex<Vec<PacketInfo>>>) {
    ui.label("Live Packet Log:");
    eframe::egui::ScrollArea::vertical().max_height(400.0).show(ui, |ui| {
        if let Ok(log) = log.lock() {
            for packet in log.iter().rev().take(100) {
                let proto_disp = ProtocolDisplay::from_packet_type(packet.packet_type.clone());
                let label = proto_disp.label();
                let colored_label = RichText::new(label)
                    .color(proto_disp.color())
                    .strong();

                let text = format_packet_line_with_label(packet);

                ui.horizontal(|ui| {
                    ui.label(colored_label);
                    ui.label(text);
                });
            }
        }
    });
}
