use crate::theme::Theme;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;
use std::ops::Range;

pub fn render_hex_dump(
    f: &mut Frame,
    area: Rect,
    raw_data: &[u8],
    highlight_range: Option<&Range<usize>>,
    scroll_offset: usize,
    cursor_byte_idx: Option<usize>,
    is_focused: bool,
    theme: &Theme,
) {
    let title = if is_focused {
        " 3: Packet Bytes (Hex Dump) [Active] [y: Copy] "
    } else {
        " 3: Packet Bytes (Hex Dump) "
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(theme.style_border(is_focused));

    let visible_lines = area.height.saturating_sub(2) as usize;
    let total_lines = (raw_data.len() + 15) / 16;

    let start_line = scroll_offset;
    let end_line = (start_line + visible_lines).min(total_lines);

    let mut lines = Vec::new();

    for line_idx in start_line..end_line {
        let line_byte_start = line_idx * 16;
        let line_byte_end = (line_byte_start + 16).min(raw_data.len());
        let chunk = &raw_data[line_byte_start..line_byte_end];

        let mut spans = Vec::new();

        // 1. Offset column: e.g. "0010  "
        spans.push(Span::styled(
            format!("{:04x}  ", line_byte_start),
            Style::default().fg(theme.hex_offset),
        ));

        // 2. Hex octets column (16 bytes, extra space after 8 bytes)
        for i in 0..16 {
            let byte_idx = line_byte_start + i;
            if i < chunk.len() {
                let byte = chunk[i];
                let is_highlighted = highlight_range
                    .map(|r| r.contains(&byte_idx))
                    .unwrap_or(false);
                let is_cursor = cursor_byte_idx == Some(byte_idx);

                let byte_style = if is_cursor {
                    Style::default()
                        .fg(theme.hex_cursor_fg)
                        .bg(theme.hex_cursor_bg)
                        .add_modifier(Modifier::BOLD)
                } else if is_highlighted {
                    Style::default()
                        .fg(theme.hex_highlight_fg)
                        .bg(theme.hex_highlight_bg)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme.hex_byte)
                };

                spans.push(Span::styled(format!("{:02x}", byte), byte_style));
                spans.push(Span::raw(if i == 7 { "  " } else { " " }));
            } else {
                // Padding for incomplete lines
                spans.push(Span::raw("  "));
                spans.push(Span::raw(if i == 7 { "  " } else { " " }));
            }
        }

        // Column separator
        spans.push(Span::styled(" ", Style::default().fg(theme.hex_offset)));

        // 3. ASCII representation column
        for i in 0..chunk.len() {
            let byte_idx = line_byte_start + i;
            let byte = chunk[i];
            let ascii_char = if (32..=126).contains(&byte) {
                byte as char
            } else {
                '.'
            };

            let is_highlighted = highlight_range
                .map(|r| r.contains(&byte_idx))
                .unwrap_or(false);
            let is_cursor = cursor_byte_idx == Some(byte_idx);

            let ascii_style = if is_cursor {
                Style::default()
                    .fg(theme.hex_cursor_fg)
                    .bg(theme.hex_cursor_bg)
                    .add_modifier(Modifier::BOLD)
            } else if is_highlighted {
                Style::default()
                    .fg(theme.hex_highlight_fg)
                    .bg(theme.hex_highlight_bg)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.hex_ascii)
            };

            spans.push(Span::styled(ascii_char.to_string(), ascii_style));
        }

        lines.push(Line::from(spans));
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            " No packet data",
            Style::default().fg(theme.hex_offset),
        )));
    }

    let p = Paragraph::new(lines).block(block);
    f.render_widget(p, area);
}
