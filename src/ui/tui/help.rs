use ratatui::{
    backend::Backend,
    layout::Rect,
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph, Wrap, Clear},
    Frame
};

/// Draws the help overlay on the terminal frame.
pub fn draw_help_overlay(f: &mut Frame<'_>) {
    let size = f.size();

    let block = Block::default()
        .title("Help - Sniffy Controls")
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::Yellow));

    let text = Paragraph::new(
        "Keyboard Controls:\n\
         q       - Quit\n\
         /       - Apply BPF filter\n\
         ?       - Toggle help\n\
         (Coming Soon)\n\
         ↑/↓     - Navigate menus\n\
         Enter   - Select item\n\
         Esc     - Cancel or return\n"
    )
    .block(block)
    .wrap(Wrap { trim: true });

    let area = Rect {
        x: size.width / 4,
        y: size.height / 4,
        width: size.width / 2,
        height: size.height / 2,
    };

    f.render_widget(Clear, area); // Clear underneath overlay
    f.render_widget(text, area);
}
