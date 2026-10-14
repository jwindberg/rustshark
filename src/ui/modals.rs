use crate::capture::InterfaceInfo;
use crate::packet::convs::{ConvRow, ConvType, Conversations};
use crate::packet::stream::StreamReassembly;
use crate::theme::Theme;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Row, Table};
use ratatui::Frame;

pub fn render_help_modal(f: &mut Frame, area: Rect, theme: &Theme) {
    let modal_area = centered_rect(75, 80, area);
    f.render_widget(Clear, modal_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Rustshark Help & Keybindings [Esc/? to close] ")
        .border_style(Style::default().fg(theme.modal_border).add_modifier(Modifier::BOLD))
        .style(Style::default().bg(theme.modal_bg).fg(theme.modal_fg));

    let content = vec![
        Line::from(vec![
            Span::styled("NAVIGATION & PANES:", Style::default().fg(theme.status_accent).add_modifier(Modifier::BOLD)),
        ]),
        Line::from("  Tab / Shift-Tab : Cycle active pane (1: Packet List -> 2: Details -> 3: Hex)"),
        Line::from("  1, 2, 3         : Jump directly to pane 1, 2, or 3"),
        Line::from("  \\               : Maximize / restore current pane"),
        Line::from("  |               : Toggle layout between vertical stack and split side-by-side"),
        Line::from("  j / Down        : Move selection down"),
        Line::from("  k / Up          : Move selection up"),
        Line::from("  PgDn / PgUp     : Scroll page down / up"),
        Line::from("  g / Home        : Jump to top"),
        Line::from("  G / End         : Jump to bottom"),
        Line::raw(""),
        Line::from(vec![
            Span::styled("FILTERING:", Style::default().fg(theme.status_accent).add_modifier(Modifier::BOLD)),
        ]),
        Line::from("  /               : Focus display filter bar"),
        Line::from("  Enter           : Apply filter"),
        Line::from("  Esc             : Clear filter / Return to packet list"),
        Line::from("  Filter syntax   : tcp, udp, dns, http, telnet, icmp, arp, ip"),
        Line::from("                    ip.addr == 192.168.1.1, ip.src == 10.0.0.1"),
        Line::from("                    tcp.port == 80, udp.port == 53, port == 23"),
        Line::from("                    frame.len > 100, frame contains \"GET\""),
        Line::from("                    &&, ||, and, or, !"),
        Line::raw(""),
        Line::from(vec![
            Span::styled("PACKET DETAILS (PANE 2):", Style::default().fg(theme.status_accent).add_modifier(Modifier::BOLD)),
        ]),
        Line::from("  Enter / Space   : Expand / collapse selected protocol or field"),
        Line::from("  e               : Expand all nodes in packet"),
        Line::from("  c               : Collapse all nodes in packet"),
        Line::from("  (Selecting a field highlights its bytes in Pane 3 Hex Dump!)"),
        Line::raw(""),
        Line::from(vec![
            Span::styled("SPECIAL FEATURES & DIALOGS:", Style::default().fg(theme.status_accent).add_modifier(Modifier::BOLD)),
        ]),
        Line::from("  s               : Follow TCP / UDP Stream"),
        Line::from("  c               : Conversations Dialog (Ethernet, IPv4, IPv6, TCP, UDP)"),
        Line::from("  p               : Capture Interfaces Dialog"),
        Line::from("  o               : Sort packet list by next column"),
        Line::from("  t               : Switch theme (Default Dark, Dracula, Solarized, Light, Base16)"),
        Line::from("  m <a-z>         : Set mark on selected packet"),
        Line::from("  ' <a-z>         : Jump to marked packet"),
        Line::from("  y               : Copy packet info / field value"),
        Line::from("  q / Ctrl-C      : Quit Rustshark"),
    ];

    let p = Paragraph::new(content).block(block);
    f.render_widget(p, modal_area);
}

pub fn render_convs_modal(
    f: &mut Frame,
    area: Rect,
    convs: &Conversations,
    active_tab: ConvType,
    selected_idx: usize,
    theme: &Theme,
) {
    let modal_area = centered_rect(85, 80, area);
    f.render_widget(Clear, modal_area);

    let title = " Conversations [Left/Right: Tab] [Up/Down: Select] [Enter: Filter] [Esc: Close] ";
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(theme.modal_border).add_modifier(Modifier::BOLD))
        .style(Style::default().bg(theme.modal_bg).fg(theme.modal_fg));

    let inner = block.inner(modal_area);
    f.render_widget(block, modal_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(5)])
        .split(inner);

    // Tab buttons
    let tabs = [
        (ConvType::Ethernet, format!("Ethernet ({})", convs.eth_convs.len())),
        (ConvType::IPv4, format!("IPv4 ({})", convs.ip4_convs.len())),
        (ConvType::IPv6, format!("IPv6 ({})", convs.ip6_convs.len())),
        (ConvType::TCP, format!("TCP ({})", convs.tcp_convs.len())),
        (ConvType::UDP, format!("UDP ({})", convs.udp_convs.len())),
    ];

    let mut tab_spans = Vec::new();
    for (ct, name) in tabs {
        let is_current = ct == active_tab;
        let style = if is_current {
            Style::default().fg(theme.header_fg).bg(theme.row_selected_bg).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.hex_offset)
        };
        tab_spans.push(Span::styled(format!("  {}  ", name), style));
        tab_spans.push(Span::raw(" "));
    }

    let tab_bar = Paragraph::new(Line::from(tab_spans)).block(Block::default().borders(Borders::BOTTOM).border_style(Style::default().fg(theme.border)));
    f.render_widget(tab_bar, chunks[0]);

    // Table of active tab
    let list: &[ConvRow] = match active_tab {
        ConvType::Ethernet => &convs.eth_convs,
        ConvType::IPv4 => &convs.ip4_convs,
        ConvType::IPv6 => &convs.ip6_convs,
        ConvType::TCP => &convs.tcp_convs,
        ConvType::UDP => &convs.udp_convs,
    };

    let header_titles = ["Address A", "Address B", "Pkts A->B", "Bytes A->B", "Pkts B->A", "Bytes B->A", "Total Pkts", "Total Bytes"];
    let header_cells = header_titles.iter().map(|&h| {
        ratatui::widgets::Cell::from(h).style(
            Style::default().fg(theme.header_fg).bg(theme.header_bg).add_modifier(Modifier::BOLD),
        )
    });
    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = list
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let is_selected = i == selected_idx;
            let style = if is_selected {
                Style::default().fg(theme.modal_selected_fg).bg(theme.modal_selected_bg).add_modifier(Modifier::BOLD)
            } else if i % 2 == 1 {
                Style::default().bg(theme.row_odd)
            } else {
                Style::default().bg(theme.row_even)
            };

            let cells = vec![
                ratatui::widgets::Cell::from(r.endpoint_a.clone()),
                ratatui::widgets::Cell::from(r.endpoint_b.clone()),
                ratatui::widgets::Cell::from(r.pkts_a_to_b.to_string()),
                ratatui::widgets::Cell::from(r.bytes_a_to_b.to_string()),
                ratatui::widgets::Cell::from(r.pkts_b_to_a.to_string()),
                ratatui::widgets::Cell::from(r.bytes_b_to_a.to_string()),
                ratatui::widgets::Cell::from(r.total_pkts.to_string()),
                ratatui::widgets::Cell::from(r.total_bytes.to_string()),
            ];
            Row::new(cells).style(style)
        })
        .collect();

    let widths = [
        Constraint::Percentage(22),
        Constraint::Percentage(22),
        Constraint::Percentage(9),
        Constraint::Percentage(10),
        Constraint::Percentage(9),
        Constraint::Percentage(10),
        Constraint::Percentage(9),
        Constraint::Percentage(9),
    ];

    let table = Table::new(rows, widths).header(header);
    f.render_widget(table, chunks[1]);
}

pub fn render_stream_modal(
    f: &mut Frame,
    area: Rect,
    stream: &StreamReassembly,
    scroll_offset: usize,
    hex_mode: bool,
    theme: &Theme,
) {
    let modal_area = centered_rect(85, 85, area);
    f.render_widget(Clear, modal_area);

    let title = format!(
        " Follow {} Stream: {} <-> {} [h: Toggle Hex] [Esc: Close] ",
        stream.protocol, stream.client_endpoint, stream.server_endpoint
    );

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(theme.modal_border).add_modifier(Modifier::BOLD))
        .style(Style::default().bg(theme.modal_bg).fg(theme.modal_fg));

    let inner = block.inner(modal_area);
    f.render_widget(block, modal_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(5)])
        .split(inner);

    // Summary banner
    let banner_spans = vec![
        Span::styled(format!("Client: {} ({} bytes)", stream.client_endpoint, stream.total_client_bytes), Style::default().fg(theme.stream_client).add_modifier(Modifier::BOLD)),
        Span::raw("  |  "),
        Span::styled(format!("Server: {} ({} bytes)", stream.server_endpoint, stream.total_server_bytes), Style::default().fg(theme.stream_server).add_modifier(Modifier::BOLD)),
        Span::raw("  |  Mode: "),
        Span::styled(if hex_mode { "HEX" } else { "ASCII" }, Style::default().fg(theme.status_key_fg).add_modifier(Modifier::BOLD)),
    ];
    f.render_widget(Paragraph::new(Line::from(banner_spans)), chunks[0]);

    // Stream lines
    let mut all_lines = Vec::new();
    for chunk in &stream.chunks {
        let color = if chunk.is_client {
            theme.stream_client
        } else {
            theme.stream_server
        };

        let prefix = if chunk.is_client { "-> " } else { "<- " };

        if hex_mode {
            for hex_chunk in chunk.data.chunks(16) {
                let hex_str: Vec<String> = hex_chunk.iter().map(|b| format!("{:02x}", b)).collect();
                let ascii_str: String = hex_chunk
                    .iter()
                    .map(|&b| if (32..=126).contains(&b) { b as char } else { '.' })
                    .collect();
                all_lines.push(Line::from(vec![
                    Span::styled(prefix, Style::default().fg(color)),
                    Span::styled(format!("{:<48}  {}", hex_str.join(" "), ascii_str), Style::default().fg(color)),
                ]));
            }
        } else {
            let text = String::from_utf8_lossy(&chunk.data);
            for l in text.lines() {
                all_lines.push(Line::from(vec![
                    Span::styled(prefix, Style::default().fg(color)),
                    Span::styled(l.to_string(), Style::default().fg(color)),
                ]));
            }
        }
    }

    let visible_height = chunks[1].height as usize;
    let end_idx = (scroll_offset + visible_height).min(all_lines.len());
    let page_lines: Vec<Line> = if scroll_offset < all_lines.len() {
        all_lines[scroll_offset..end_idx].to_vec()
    } else {
        Vec::new()
    };

    let p = Paragraph::new(page_lines);
    f.render_widget(p, chunks[1]);
}

pub fn render_ifaces_modal(
    f: &mut Frame,
    area: Rect,
    ifaces: &[InterfaceInfo],
    selected_idx: usize,
    theme: &Theme,
) {
    let modal_area = centered_rect(65, 60, area);
    f.render_widget(Clear, modal_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Capture Interfaces [Up/Down: Select] [Enter: Start Capture] [Esc: Close] ")
        .border_style(Style::default().fg(theme.modal_border).add_modifier(Modifier::BOLD))
        .style(Style::default().bg(theme.modal_bg).fg(theme.modal_fg));

    let rows: Vec<Row> = ifaces
        .iter()
        .enumerate()
        .map(|(i, iface)| {
            let is_selected = i == selected_idx;
            let style = if is_selected {
                Style::default().fg(theme.modal_selected_fg).bg(theme.modal_selected_bg).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.modal_fg)
            };
            Row::new(vec![
                ratatui::widgets::Cell::from(iface.index.to_string()),
                ratatui::widgets::Cell::from(iface.name.clone()),
                ratatui::widgets::Cell::from(iface.description.clone()),
            ]).style(style)
        })
        .collect();

    let header = Row::new(vec![
        ratatui::widgets::Cell::from("No."),
        ratatui::widgets::Cell::from("Name"),
        ratatui::widgets::Cell::from("Description"),
    ]).style(Style::default().fg(theme.header_fg).bg(theme.header_bg).add_modifier(Modifier::BOLD));

    let table = Table::new(rows, [Constraint::Length(6), Constraint::Length(16), Constraint::Min(20)])
        .header(header)
        .block(block);

    f.render_widget(table, modal_area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
