use eframe::egui;

pub fn filter_input(
    ui: &mut egui::Ui,
    filters: &[String],
    selected: &mut Option<String>,
) {
    ui.horizontal(|ui| {
        ui.label("BPF Filter:");
        egui::ComboBox::from_id_salt("bpf_filter_combo")
            .selected_text(
                selected
                    .as_deref()
                    .unwrap_or("Select filter"),
            )
            .show_ui(ui, |ui| {
                for f in filters {
                    ui.selectable_value(selected, Some(f.clone()), f);
                }
            });
    });
}
