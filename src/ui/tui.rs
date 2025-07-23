use std::{
    collections::{HashMap, VecDeque},
    io::{self, stdout},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use crossterm::event::{self, Event, KeyCode};
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
    Terminal,
};

use crate::packet::{PacketInfo, PacketType};

static MAX_LINES: usize = 30;

lazy_static::lazy_static! {
    static ref PACKET_LOG: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(VecDeque::new()));
}

pub fn initialize_tui() -> Result<(), String> {
    enable_raw_mode().map_err(|e| e.to_string())?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn spawn_input_handler(running: Arc<AtomicBool>) {
    thread::spawn(move || {
        loop {
            if event::poll(Duration::from_millis(100)).unwrap_or(false) {
                if let Ok(Event::Key(key)) = event::read() {
                    if let KeyCode::Char('q') | KeyCode::Char('Q') = key.code {
                        running.store(false, Ordering::SeqCst);
                        break;
                    }
                }
            }

            if !running.load(Ordering::SeqCst) {
                break;
            }
        }
    });
}

pub fn start_ui_thread(
    running: Arc<AtomicBool>,
    packet_counts: Arc<Mutex<HashMap<PacketType, usize>>>,
) {
    let log = Arc::clone(&PACKET_LOG);

    thread::spawn(move || {
        let mut stdout = stdout();
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

            terminal
                .draw(|f| {
                    let size = f.size();
                    let chunks = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)].as_ref())
                        .split(size);

                    // Packet log panel
                    let log_text = lines
                        .iter()
                        .rev()
                        .map(|line| line.as_str())
                        .collect::<Vec<_>>()
                        .join("\n");

                    let log_block = Paragraph::new(log_text)
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title("Sniffy - Packet Log (press 'q' to quit)"),
                        )
                        .style(Style::default().fg(Color::White));

                    f.render_widget(log_block, chunks[0]);

                    // Stats panel
                    let stats_text = if counts_snapshot.is_empty() {
                        "No packets yet.".to_string()
                    } else {
                        let mut summary = String::new();
                        for (ptype, count) in counts_snapshot.iter() {
                            summary.push_str(&format!("{:<10} {}\n", format!("{}", ptype), count));
                        }
                        summary
                    };

                    let stats_block = Paragraph::new(stats_text)
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title("Live Packet Stats"),
                        )
                        .style(Style::default().fg(Color::Green));

                    f.render_widget(stats_block, chunks[1]);
                })
                .expect("Failed to draw UI");

            thread::sleep(Duration::from_millis(100));
        }

        drop(terminal);
        disable_raw_mode().expect("Failed to disable raw mode");
        execute!(stdout, LeaveAlternateScreen).expect("Failed to leave alternate screen");
    });
}

pub fn display_packet_info(info: &PacketInfo) {
    let summary = format_packet_line(info);
    let mut log = PACKET_LOG.lock().unwrap();
    log.push_back(summary);
    if log.len() > MAX_LINES {
        log.pop_front();
    }
}

pub fn print_final_summary(counts: Arc<Mutex<HashMap<PacketType, usize>>>) {
    disable_raw_mode().unwrap();
    let mut stdout = stdout();
    execute!(stdout, LeaveAlternateScreen).expect("Failed to leave alternate screen");

    println!("\nPacket summary:");
    let counts = counts.lock().unwrap();
    for (ptype, count) in counts.iter() {
        println!("  {}: {}", ptype, count);
    }
}

fn format_packet_line(info: &PacketInfo) -> String {
    let macs = match (&info.src_mac, &info.dst_mac) {
        (Some(src), Some(dst)) => format!("MAC {} -> {}", mac_to_str(src), mac_to_str(dst)),
        _ => "MAC [n/a]".to_string(),
    };

    let ips = match (&info.src_ip, &info.dst_ip) {
        (Some(src), Some(dst)) => format!("{} -> {}", src, dst),
        _ => "[no IP]".to_string(),
    };

    let ports = match (info.src_port, info.dst_port) {
        (Some(s), Some(d)) => format!("ports {} -> {}", s, d),
        _ => String::new(),
    };

    let mut summary = format!("{} | {} | {} | {}", info.packet_type, macs, ips, ports);

    if let Some(queries) = &info.dns_queries {
        summary.push_str(&format!(" | DNS: {}", queries.join(", ")));
    }

    summary
}

fn mac_to_str(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
