use crate::theme::Theme;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

pub fn render_filter_bar(
    f: &mut Frame,
    area: Rect,
    input: &str,
    cursor_pos: usize,
    is_focused: bool,
    is_valid: bool,
    theme: &Theme,
) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(10),
            Constraint::Length(28),
        ])
        .split(area);

    let (border_color, status_text) = if input.trim().is_empty() {
        (theme.border, " [Apply: Enter] ")
    } else if is_valid {
        (theme.filter_valid_bg, " [Valid: Enter] ")
    } else {
        (theme.filter_invalid_bg, " [Invalid Filter] ")
    };

    let title = if is_focused {
        Span::styled(" Display Filter [/] ", Style::default().fg(theme.status_accent).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" Display Filter [/] ", Style::default().fg(theme.fg))
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(if is_focused {
            Style::default().fg(border_color).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.border)
        });

    let display_text = if input.is_empty() && !is_focused {
        Span::styled(
            "Enter Wireshark display filter e.g. ip.addr == 192.168.1.1, tcp.port == 80, telnet, or text search...",
            Style::default().fg(theme.hex_offset),
        )
    } else {
        Span::styled(input, Style::default().fg(theme.fg))
    };

    let p = Paragraph::new(Line::from(display_text)).block(block);
    f.render_widget(p, chunks[0]);

    // Render helper button badges on right side
    let help_line = Line::from(vec![
        Span::styled(status_text, Style::default().fg(if is_valid { theme.proto_udp } else { theme.proto_icmp })),
        Span::styled("Esc", Style::default().fg(theme.status_key_fg).add_modifier(Modifier::BOLD)),
        Span::raw(":Clear "),
    ]);
    let help_p = Paragraph::new(help_line).block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(theme.border)));
    f.render_widget(help_p, chunks[1]);

    if is_focused {
        // Position the cursor inside the input box (accounting for border offset)
        f.set_cursor_position((
            chunks[0].x + 1 + cursor_pos as u16,
            chunks[0].y + 1,
        ));
    }
}
