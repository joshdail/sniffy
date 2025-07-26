mod capture;
mod core;
mod packet;
mod ui;
mod cli;

use clap::Parser;

use crate::cli::CliArgs;
use crate::core::runner::{setup_savefile, run_packet_loop};
use crate::core::signal::setup_ctrlc_handler;
use crate::packet::PacketType;
use crate::ui::tui::input::spawn_input_handler;
use crate::ui::tui::log::print_final_summary;
use crate::ui::tui::render::start_ui_thread;
use crate::ui::tui::state::{UiState, UiMode};
use crate::ui::device::get_available_devices;

use pcap::Capture;

use std::{
    collections::HashMap,
    process,
    sync::{
        atomic::AtomicBool,
        Arc, Mutex,
    },
};

fn main() {
    let args = CliArgs::parse();
    // TODO: Wire debug_enabled as a CLI arg
    let debug_enabled = false;
    let running = Arc::new(AtomicBool::new(true));
    setup_ctrlc_handler(Arc::clone(&running));

    // Safely fetch device list up front
    let devices = match get_available_devices() {
        Ok(devs) if !devs.is_empty() => devs,
        Ok(_) => {
            eprintln!("❌ No interfaces found.");
            return;
        }
        Err(e) => {
            eprintln!("❌ Failed to list interfaces: {}", e);
            return;
        }
    };

    // Attempt to open a dummy session to pass to the capture loop
    let dummy_cap = match Capture::from_device(devices[0].as_str()) {
        Ok(dev) => dev.promisc(true).snaplen(65535).open(),
        Err(e) => {
            eprintln!("❌ Failed to create capture for '{}': {}", devices[0], e);
            return;
        }
    };

    let dummy_cap = match dummy_cap {
        Ok(capture) => capture,
        Err(e) => {
            eprintln!("❌ Failed to open capture: {}", e);
            return;
        }
    };

    let cap = Arc::new(Mutex::new(dummy_cap));
    let savefile = setup_savefile(&args, &cap);
    let packet_counts = Arc::new(Mutex::new(HashMap::<PacketType, usize>::new()));

    // Initial UI state with DeviceMenu or fallback Capture mode
    let initial_mode = if !devices.is_empty() {
        UiMode::DeviceMenu {
            options: devices,
            selected: 0,
        }
    } else {
        UiMode::Capture
    };

    let ui_state = Arc::new(Mutex::new(UiState {
        mode: initial_mode,
        error_msg: Some("No suitable network interfaces found.".to_string()),
        info_msg: None,
    }));

    let input_handle = spawn_input_handler(
        Arc::clone(&running),
        Arc::clone(&cap),
        Arc::clone(&ui_state),
    );

    let ui_handle = start_ui_thread(
        Arc::clone(&running),
        Arc::clone(&packet_counts),
        Arc::clone(&ui_state),
    );

    if let Err(e) = run_packet_loop(running.clone(), cap, savefile, Arc::clone(&packet_counts), debug_enabled) {
        eprintln!("❌ Packet loop error: {}", e);
    }

    if let Err(e) = input_handle.join() {
        eprintln!("⚠️ Input thread panicked: {:?}", e);
    }
    if let Err(e) = ui_handle.join() {
        eprintln!("⚠️ UI thread panicked: {:?}", e);
    }

    print_final_summary(packet_counts);
    process::exit(0);
}
