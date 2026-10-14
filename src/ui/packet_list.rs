use crate::packet::PacketRecord;
use crate::theme::Theme;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, Row, Table};
use ratatui::Frame;

pub fn render_packet_list(
    f: &mut Frame,
    area: Rect,
    packets: &[&PacketRecord],
    selected_idx: usize,
    scroll_offset: usize,
    is_focused: bool,
    theme: &Theme,
    sort_column: usize,
    sort_desc: bool,
    marks: &std::collections::HashMap<char, usize>,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(if is_focused {
            " 1: Packet List [Active] "
        } else {
            " 1: Packet List "
        })
        .border_style(theme.style_border(is_focused));

    let header_titles = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"];
    let header_cells = header_titles.iter().enumerate().map(|(i, &h)| {
        let title = if i == sort_column {
            let arrow = if sort_desc { " v" } else { " ^" };
            format!("{}{}", h, arrow)
        } else {
            h.to_string()
        };
        Cell::from(title).style(
            Style::default()
                .fg(theme.header_fg)
                .bg(theme.header_bg)
                .add_modifier(Modifier::BOLD),
        )
    });
    let header = Row::new(header_cells).height(1);

    let visible_height = area.height.saturating_sub(2) as usize; // subtracting borders
    let max_rows = visible_height.saturating_sub(1); // subtracting header

    let start_idx = scroll_offset;
    let end_idx = (start_idx + max_rows).min(packets.len());

    let mut rows = Vec::new();
    for i in start_idx..end_idx {
        let pkt = packets[i];
        let is_selected = i == selected_idx;

        // Check if packet has mark
        let mark_char = marks.iter().find(|(_, idx)| **idx == i).map(|(c, _)| *c);
        let num_str = if let Some(mc) = mark_char {
            format!("*{} {}", mc, pkt.summary.num)
        } else {
            pkt.summary.num.to_string()
        };

        let proto_color = theme.proto_color(&pkt.summary.protocol);

        let row_style = if is_selected {
            Style::default()
                .fg(theme.row_selected_fg)
                .bg(theme.row_selected_bg)
                .add_modifier(Modifier::BOLD)
        } else if mark_char.is_some() {
            Style::default().fg(theme.row_marked_fg).bg(theme.row_marked_bg)
        } else if i % 2 == 1 {
            Style::default().bg(theme.row_odd)
        } else {
            Style::default().bg(theme.row_even)
        };

        let cells = vec![
            Cell::from(num_str),
            Cell::from(format!("{:.6}", pkt.summary.rel_time_secs)),
            Cell::from(pkt.summary.src.as_str()),
            Cell::from(pkt.summary.dst.as_str()),
            Cell::from(pkt.summary.protocol.as_str()).style(if is_selected {
                Style::default().fg(theme.row_selected_fg).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(proto_color).add_modifier(Modifier::BOLD)
            }),
            Cell::from(pkt.summary.length.to_string()),
            Cell::from(pkt.summary.info.as_str()),
        ];

        rows.push(Row::new(cells).style(row_style));
    }

    let widths = [
        Constraint::Length(8),   // No.
        Constraint::Length(12),  // Time
        Constraint::Length(22),  // Source
        Constraint::Length(22),  // Destination
        Constraint::Length(10),  // Protocol
        Constraint::Length(8),   // Length
        Constraint::Min(20),     // Info
    ];

    let table = Table::new(rows, widths).header(header).block(block);
    f.render_widget(table, area);
}
