use std::{
    collections::{HashMap, VecDeque},
    io::{stdout, Stdout},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crossterm::{
    execute,
    terminal::{enable_raw_mode, disable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::{Block, Borders, Clear, Paragraph, List, ListItem, ListState},
    Terminal, Frame,
};

use crate::packet::PacketType;
use crate::ui::tui::{draw_help_overlay, PACKET_LOG};
use super::state::{UiMode, UiState};

pub fn start_ui_thread(
    running: Arc<AtomicBool>,
    packet_counts: Arc<Mutex<HashMap<PacketType, usize>>>,
    ui_state: Arc<Mutex<UiState>>,
) -> JoinHandle<()> {
    let log = Arc::clone(&PACKET_LOG);
    let state = Arc::clone(&ui_state);

    thread::spawn(move || {
        let mut stdout = stdout();

        enable_raw_mode().expect("Failed to enable raw mode");
        execute!(stdout, EnterAlternateScreen).expect("Failed to enter alternate screen");

        let backend = CrosstermBackend::new(&mut stdout);
        let mut terminal = Terminal::new(backend).expect("Failed to create terminal");

        while running.load(Ordering::SeqCst) {
            let lines = {
                let log_guard = log.lock().unwrap();
                log_guard.clone()
            };

            let counts_snapshot = {
                let counts = packet_counts.lock().unwrap();
                counts.clone()
            };

            let ui_guard = match state.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    eprintln!("Failed to lock UI state: {}", e);
                    continue;
                }
            };

            let mode = ui_guard.mode.clone();
            let error_msg = ui_guard.error_msg.clone();
            drop(ui_guard);

            if let Err(e) = terminal.draw(|f| {
                render_ui_by_mode(f, &mode, &lines, &counts_snapshot, error_msg.as_ref())
            }) {
                eprintln!("Terminal draw failed: {}", e);
            }

            thread::sleep(Duration::from_millis(33));
        }

        drop(terminal);
        let _ = disable_raw_mode();
        let _ = execute!(stdout, LeaveAlternateScreen);
    })
}

fn render_ui_by_mode(
    f: &mut Frame<'_>,
    mode: &UiMode,
    lines: &VecDeque<String>,
    counts: &HashMap<PacketType, usize>,
    error_msg: Option<&String>,
) {
    match mode {
        UiMode::Capture => draw_main_ui(f, lines, counts, error_msg),
        UiMode::HelpOverlay => draw_help_overlay(f),
        UiMode::DeviceMenu { options, selected } => draw_device_menu(f, options, *selected),
        UiMode::FilterMenu { options, selected, .. } => draw_filter_menu(f, options, *selected),
    }
}

fn draw_main_ui(
    f: &mut Frame<'_>,
    lines: &VecDeque<String>,
    counts: &HashMap<PacketType, usize>,
    error_msg: Option<&String>,
) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)].as_ref())
        .split(f.size());

    draw_packet_log(f, &chunks[0], lines);
    draw_stats_panel(f, &chunks[1], counts);

    if let Some(msg) = error_msg {
        let area = Rect {
            x: 5,
            y: 2,
            width: f.size().width.saturating_sub(10),
            height: 3,
        };

        let block = Paragraph::new(msg.clone())
            .block(Block::default().title("Error").borders(Borders::ALL))
            .style(Style::default().fg(Color::Red));

        f.render_widget(Clear, area); // Clear background under error
        f.render_widget(block, area);
    }
}

fn draw_packet_log(f: &mut Frame<'_>, area: &Rect, lines: &VecDeque<String>) {
    let log_text = lines.iter().rev().map(String::as_str).collect::<Vec<_>>().join("\n");

    let block = Paragraph::new(log_text)
        .block(Block::default().title("Sniffy - Packet Log (q = quit, ? = help)").borders(Borders::ALL))
        .style(Style::default().fg(Color::White));

    f.render_widget(block, *area);
}

fn draw_stats_panel(f: &mut Frame<'_>, area: &Rect, counts: &HashMap<PacketType, usize>) {
    let stats_text = if counts.is_empty() {
        "No packets yet.".to_string()
    } else {
        counts.iter().map(|(ptype, count)| format!("{:<10} {}\n", ptype, count)).collect()
    };

    let block = Paragraph::new(stats_text)
        .block(Block::default().title("Live Packet Stats").borders(Borders::ALL))
        .style(Style::default().fg(Color::Green));

    f.render_widget(block, *area);
}

fn draw_device_menu(f: &mut Frame<'_>, options: &[String], selected: usize) {
    let items: Vec<ListItem> = options.iter().map(|d| ListItem::new(d.clone())).collect();

    let list = List::new(items)
        .block(Block::default().title("Select Interface").borders(Borders::ALL))
        .highlight_style(Style::default().fg(Color::Yellow).bg(Color::Blue));

    let mut state = ListState::default();
    state.select(Some(selected));

    f.render_stateful_widget(list, f.size(), &mut state);
}

fn draw_filter_menu(f: &mut Frame<'_>, options: &[(String, String)], selected: usize) {
    let items: Vec<ListItem> = options
        .iter()
        .map(|(label, _)| ListItem::new(label.clone()))
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title("Select BPF Filter (Enter to apply, Esc to cancel)")
                .borders(Borders::ALL),
        )
        .highlight_style(Style::default().fg(Color::Yellow).bg(Color::Blue));

    let mut state = ListState::default();
    state.select(Some(selected));

    f.render_stateful_widget(list, f.size(), &mut state);
}