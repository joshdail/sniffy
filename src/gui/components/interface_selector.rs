use eframe::egui;

pub fn interface_selector(
    ui: &mut egui::Ui,
    interfaces: &[String],
    selected: &mut Option<String>,
) {
    ui.horizontal(|ui| {
        ui.label("Interface:");
        egui::ComboBox::from_id_salt("interface_combo")
            .selected_text(
                selected
                    .as_ref()
                    .map(|s| s.as_str())
                    .unwrap_or("Select interface"),
            )
            .show_ui(ui, |ui| {
                for iface in interfaces {
                    ui.selectable_value(selected, Some(iface.clone()), iface);
                }
            });
    });
}
