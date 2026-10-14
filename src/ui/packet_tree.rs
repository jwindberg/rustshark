use crate::packet::TreeNode;
use crate::theme::Theme;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

pub fn render_packet_tree(
    f: &mut Frame,
    area: Rect,
    visible_nodes: &[(Vec<usize>, usize, &TreeNode)],
    selected_row: usize,
    scroll_offset: usize,
    is_focused: bool,
    theme: &Theme,
) {
    let title = if is_focused {
        " 2: Packet Details [Active] [Enter: Toggle] [e: Expand All] [c: Collapse All] "
    } else {
        " 2: Packet Details "
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(theme.style_border(is_focused));

    let visible_height = area.height.saturating_sub(2) as usize;
    let end_idx = (scroll_offset + visible_height).min(visible_nodes.len());

    let mut lines = Vec::new();
    for i in scroll_offset..end_idx {
        let (_path, depth, node) = &visible_nodes[i];
        let is_selected = i == selected_row;

        let indent = "  ".repeat(*depth);
        let icon = if node.children.is_empty() {
            "  "
        } else if node.expanded {
            "[-] "
        } else {
            "[+] "
        };

        let row_style = if is_selected {
            Style::default()
                .fg(theme.tree_selected_fg)
                .bg(theme.tree_selected_bg)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.tree_fg)
        };

        let mut spans = vec![
            Span::raw(indent),
            Span::styled(
                icon,
                if is_selected {
                    Style::default().fg(theme.tree_selected_fg).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme.status_accent).add_modifier(Modifier::BOLD)
                },
            ),
        ];

        if !node.field_name.is_empty() && !node.field_val.is_empty() {
            spans.push(Span::styled(
                &node.title,
                row_style,
            ));
        } else {
            spans.push(Span::styled(&node.title, row_style));
        }

        lines.push(Line::from(spans));
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            " No packet selected",
            Style::default().fg(theme.hex_offset),
        )));
    }

    let p = Paragraph::new(lines).block(block);
    f.render_widget(p, area);
}
