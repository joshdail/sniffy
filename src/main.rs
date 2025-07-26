mod capture;
mod core;
mod packet;
mod gui;
mod cli;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([960.0, 640.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Sniffy - GUI Packet Sniffer",
        options,
        Box::new(|cc| Ok(Box::new(gui::app::SniffyApp::new(cc)))),
    )
}
