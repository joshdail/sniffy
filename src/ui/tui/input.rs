use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crossterm::event::{self, Event, KeyCode, KeyEvent};
use pcap::{Capture, Device};

use crate::core::capture_loop::reinitialize_capture;
use crate::ui::filter::get_bpf_filter_suggestions;
use crate::ui::tui::state::{UiMode, UiState};

pub fn spawn_input_handler(
    running: Arc<AtomicBool>,
    cap: Arc<Mutex<Capture<pcap::Active>>>,
    ui_state: Arc<Mutex<UiState>>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        while running.load(Ordering::SeqCst) {
            if event::poll(Duration::from_millis(100)).unwrap_or(false) {
                if let Ok(Event::Key(key)) = event::read() {
                    if let Ok(mut state) = ui_state.lock() {
                        state.clear_error();
                    }
                    handle_key_event(key, &running, &cap, &ui_state);
                }
            }
        }
    })
}

fn handle_key_event(
    key: KeyEvent,
    running: &Arc<AtomicBool>,
    cap: &Arc<Mutex<Capture<pcap::Active>>>,
    ui_state: &Arc<Mutex<UiState>>,
) {
    match key.code {
        KeyCode::Char('q') | KeyCode::Char('Q') => running.store(false, Ordering::SeqCst),
        KeyCode::Char('?') => toggle_help(ui_state),
        KeyCode::Char('/') => open_filter_menu(ui_state),
        KeyCode::Up | KeyCode::Down | KeyCode::Enter | KeyCode::Esc => {
            handle_menu_navigation(key, ui_state, cap)
        }
        _ => {}
    }
}

fn toggle_help(ui_state: &Arc<Mutex<UiState>>) {
    if let Ok(mut state) = ui_state.lock() {
        state.mode = match state.mode {
            UiMode::HelpOverlay => UiMode::Capture,
            _ => UiMode::HelpOverlay,
        };
    }
}

fn open_filter_menu(ui_state: &Arc<Mutex<UiState>>) {
    if let Ok(mut state) = ui_state.lock() {
        let current_iface = match &state.mode {
            UiMode::DeviceMenu { options, selected } => {
                options.get(*selected).cloned().unwrap_or_default()
            }
            _ => String::new(), // fallback if no interface selected
        };

        let options = get_bpf_filter_suggestions(&current_iface);

        state.mode = UiMode::FilterMenu {
            interface: current_iface,
            input: String::new(),
            cursor_pos: 0,
            options,
            selected: 0,
        };
    }
}

fn handle_menu_navigation(
    key: KeyEvent,
    ui_state: &Arc<Mutex<UiState>>,
    cap: &Arc<Mutex<Capture<pcap::Active>>>,
) {
    let mut state = match ui_state.lock() {
        Ok(s) => s,
        Err(_) => return,
    };

    match &mut state.mode {
        UiMode::DeviceMenu { options, selected } => match key.code {
            KeyCode::Up => {
                if *selected > 0 {
                    *selected -= 1;
                }
            }
            KeyCode::Down => {
                if *selected < options.len().saturating_sub(1) {
                    *selected += 1;
                }
            }
            KeyCode::Enter => {
                // Clone device name to avoid borrowing state.mode while using state later
                let device = match options.get(*selected).cloned() {
                    Some(d) => d,
                    None => {
                        state.mode = UiMode::Capture;
                        return;
                    }
                };

                // Release mutable borrow of state.mode here
                drop(state);

                // Re-lock to update capture and UI info safely
                let mut state = match ui_state.lock() {
                    Ok(s) => s,
                    Err(_) => return,
                };

                match reinitialize_capture(&device) {
                    Ok(new_capture) => {
                        if let Ok(mut cap_guard) = cap.lock() {
                            *cap_guard = new_capture;
                            state.set_info(format!("✅ Switched to device: {}", device));
                        } else {
                            state.set_error("Failed to lock capture mutex.".to_string());
                        }
                    }
                    Err(e) => {
                        state.set_error(format!("Failed to switch device: {}", e));
                    }
                }

                state.mode = UiMode::Capture;
            }
            KeyCode::Esc => {
                state.mode = UiMode::Capture;
            }
            _ => {}
        },
        UiMode::FilterMenu { options, selected, .. } => match key.code {
            KeyCode::Up => {
                if *selected > 0 {
                    *selected -= 1;
                }
            }
            KeyCode::Down => {
                if *selected < options.len().saturating_sub(1) {
                    *selected += 1;
                }
            }
            KeyCode::Enter => {
                // Clone label and filter_expr out of options first
                let (label, filter_expr) = match options.get(*selected).cloned() {
                    Some(t) => t,
                    None => {
                        state.mode = UiMode::Capture;
                        return;
                    }
                };

                // Drop state lock to avoid double mutable borrow during filter apply
                drop(state);

                // Lock again to update capture and UI state
                let mut state = match ui_state.lock() {
                    Ok(s) => s,
                    Err(_) => return,
                };

                let filter_result = {
                    let mut cap_lock = match cap.lock() {
                        Ok(lock) => lock,
                        Err(e) => {
                            state.set_error(format!("Failed to lock capture: {}", e));
                            state.mode = UiMode::Capture;
                            return;
                        }
                    };
                    cap_lock.filter(&filter_expr, true)
                };

                match filter_result {
                    Ok(_) => state.set_info(format!("✅ Applied filter: '{}' ({})", filter_expr, label)),
                    Err(e) => state.set_error(format!("❌ Failed to apply filter: {}", e)),
                }

                state.mode = UiMode::Capture;
            }
            KeyCode::Esc => {
                state.mode = UiMode::Capture;
            }
            _ => {}
        },
        UiMode::HelpOverlay => {
            if key.code == KeyCode::Esc {
                state.mode = UiMode::Capture;
            }
        }
        _ => {}
    }
}
