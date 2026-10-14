use crate::theme::Theme;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

pub fn render_status_bar(
    f: &mut Frame,
    area: Rect,
    source_name: &str,
    total_packets: usize,
    filtered_packets: usize,
    selected_packet_num: Option<usize>,
    selected_packet_len: Option<usize>,
    active_pane: usize,
    theme: &Theme,
    status_msg: Option<&str>,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(area);

    // Line 1: Source, status message, counts, active pane
    let mut left_spans = vec![
        Span::styled(format!(" {} ", source_name), Style::default().fg(theme.header_fg).bg(theme.header_bg).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
    ];

    if let Some(msg) = status_msg {
        left_spans.push(Span::styled(msg, Style::default().fg(theme.status_key_fg).add_modifier(Modifier::BOLD)));
        left_spans.push(Span::raw(" | "));
    }

    let pct = if total_packets > 0 {
        (filtered_packets * 100) / total_packets
    } else {
        100
    };

    left_spans.push(Span::styled(
        format!("Packets: {}/{} ({}%)", filtered_packets, total_packets, pct),
        Style::default().fg(theme.status_fg),
    ));

    if let (Some(num), Some(len)) = (selected_packet_num, selected_packet_len) {
        left_spans.push(Span::raw(" | "));
        left_spans.push(Span::styled(
            format!("Pkt #{} ({} B)", num, len),
            Style::default().fg(theme.status_accent),
        ));
    }

    let p1_style = if active_pane == 1 {
        Style::default().fg(theme.row_selected_fg).bg(theme.row_selected_bg).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme.hex_offset)
    };
    let p2_style = if active_pane == 2 {
        Style::default().fg(theme.row_selected_fg).bg(theme.row_selected_bg).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme.hex_offset)
    };
    let p3_style = if active_pane == 3 {
        Style::default().fg(theme.row_selected_fg).bg(theme.row_selected_bg).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme.hex_offset)
    };

    let panes_spans = vec![
        Span::styled(" [1: List] ", p1_style),
        Span::styled(" [2: Tree] ", p2_style),
        Span::styled(" [3: Hex] ", p3_style),
    ];

    let row1 = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(20), Constraint::Length(32)])
        .split(chunks[0]);

    f.render_widget(Paragraph::new(Line::from(left_spans)).style(Style::default().bg(theme.status_bg)), row1[0]);
    f.render_widget(Paragraph::new(Line::from(panes_spans)).style(Style::default().bg(theme.status_bg)), row1[1]);

    // Line 2: Keyboard shortcuts guide
    let shortcuts = vec![
        Span::styled("Tab", Style::default().fg(theme.status_key_fg).add_modifier(Modifier::BOLD)),
        Span::raw(":Pane "),
        Span::styled("/", Style::default().fg(theme.status_key_fg).add_modifier(Modifier::BOLD)),
        Span::raw(":Filter "),
        Span::styled("s", Style::default().fg(theme.status_key_fg).add_modifier(Modifier::BOLD)),
        Span::raw(":Stream "),
        Span::styled("c", Style::default().fg(theme.status_key_fg).add_modifier(Modifier::BOLD)),
        Span::raw(":Convs "),
        Span::styled("p", Style::default().fg(theme.status_key_fg).add_modifier(Modifier::BOLD)),
        Span::raw(":Ifaces "),
        Span::styled("o", Style::default().fg(theme.status_key_fg).add_modifier(Modifier::BOLD)),
        Span::raw(":Sort "),
        Span::styled("\\", Style::default().fg(theme.status_key_fg).add_modifier(Modifier::BOLD)),
        Span::raw(":Max "),
        Span::styled("|", Style::default().fg(theme.status_key_fg).add_modifier(Modifier::BOLD)),
        Span::raw(":Layout "),
        Span::styled("?", Style::default().fg(theme.status_key_fg).add_modifier(Modifier::BOLD)),
        Span::raw(":Help "),
        Span::styled("q", Style::default().fg(theme.status_key_fg).add_modifier(Modifier::BOLD)),
        Span::raw(":Quit"),
    ];

    f.render_widget(Paragraph::new(Line::from(shortcuts)).style(Style::default().bg(theme.status_bg)), chunks[1]);
}
