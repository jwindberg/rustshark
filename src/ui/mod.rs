pub mod filter_bar;
pub mod hex_dump;
pub mod modals;
pub mod packet_list;
pub mod packet_tree;
pub mod status_bar;

use crate::app::{ActiveModal, ActivePane, App, LayoutMode};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::Frame;

pub fn render_ui(f: &mut Frame, app: &App) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Filter Bar
            Constraint::Min(5),    // Data Panes
            Constraint::Length(2), // Status Bar
        ])
        .split(f.area());

    let filter_area = main_layout[0];
    let content_area = main_layout[1];
    let status_area = main_layout[2];

    // 1. Render Filter Bar
    filter_bar::render_filter_bar(
        f,
        filter_area,
        &app.filter_input,
        app.filter_cursor_pos,
        app.is_filter_focused,
        app.is_filter_valid,
        &app.theme,
    );

    // 2. Render Main Content Panes
    let filtered_packets = app.filtered_packet_refs();
    let current_packet = app.current_packet();

    let visible_nodes = current_packet
        .map(|p| p.tree.visible_nodes())
        .unwrap_or_default();

    let highlight_range = if let Some(row) = visible_nodes.get(app.tree_selected_row) {
        row.2.byte_range.as_ref()
    } else {
        None
    };

    let empty_slice: &[u8] = &[];
    let raw_data = current_packet.map(|p| p.raw_data.as_slice()).unwrap_or(empty_slice);

    if let Some(max_pane) = app.maximized_pane {
        // Maximized layout
        match max_pane {
            ActivePane::PacketList => {
                packet_list::render_packet_list(
                    f,
                    content_area,
                    &filtered_packets,
                    app.packet_list_selected_idx,
                    app.packet_list_scroll_offset,
                    app.active_pane == ActivePane::PacketList,
                    &app.theme,
                    app.sort_column,
                    app.sort_desc,
                    &app.marks,
                );
            }
            ActivePane::PacketTree => {
                packet_tree::render_packet_tree(
                    f,
                    content_area,
                    &visible_nodes,
                    app.tree_selected_row,
                    app.tree_scroll_offset,
                    app.active_pane == ActivePane::PacketTree,
                    &app.theme,
                );
            }
            ActivePane::HexDump => {
                hex_dump::render_hex_dump(
                    f,
                    content_area,
                    raw_data,
                    highlight_range,
                    app.hex_scroll_offset,
                    app.hex_cursor_byte,
                    app.active_pane == ActivePane::HexDump,
                    &app.theme,
                );
            }
        }
    } else {
        match app.layout_mode {
            LayoutMode::VerticalStack => {
                let pane_splits = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Percentage(app.pane_list_pct),
                        Constraint::Percentage(app.pane_tree_pct),
                        Constraint::Percentage(app.pane_hex_pct),
                    ])
                    .split(content_area);

                packet_list::render_packet_list(
                    f,
                    pane_splits[0],
                    &filtered_packets,
                    app.packet_list_selected_idx,
                    app.packet_list_scroll_offset,
                    app.active_pane == ActivePane::PacketList,
                    &app.theme,
                    app.sort_column,
                    app.sort_desc,
                    &app.marks,
                );

                packet_tree::render_packet_tree(
                    f,
                    pane_splits[1],
                    &visible_nodes,
                    app.tree_selected_row,
                    app.tree_scroll_offset,
                    app.active_pane == ActivePane::PacketTree,
                    &app.theme,
                );

                hex_dump::render_hex_dump(
                    f,
                    pane_splits[2],
                    raw_data,
                    highlight_range,
                    app.hex_scroll_offset,
                    app.hex_cursor_byte,
                    app.active_pane == ActivePane::HexDump,
                    &app.theme,
                );
            }
            LayoutMode::SideBySide => {
                let top_bottom = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(content_area);

                packet_list::render_packet_list(
                    f,
                    top_bottom[0],
                    &filtered_packets,
                    app.packet_list_selected_idx,
                    app.packet_list_scroll_offset,
                    app.active_pane == ActivePane::PacketList,
                    &app.theme,
                    app.sort_column,
                    app.sort_desc,
                    &app.marks,
                );

                let bottom_split = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(top_bottom[1]);

                packet_tree::render_packet_tree(
                    f,
                    bottom_split[0],
                    &visible_nodes,
                    app.tree_selected_row,
                    app.tree_scroll_offset,
                    app.active_pane == ActivePane::PacketTree,
                    &app.theme,
                );

                hex_dump::render_hex_dump(
                    f,
                    bottom_split[1],
                    raw_data,
                    highlight_range,
                    app.hex_scroll_offset,
                    app.hex_cursor_byte,
                    app.active_pane == ActivePane::HexDump,
                    &app.theme,
                );
            }
        }
    }

    // 3. Render Status Bar
    let selected_num = current_packet.map(|p| p.summary.num);
    let selected_len = current_packet.map(|p| p.summary.length);
    let active_pane_num = match app.active_pane {
        ActivePane::PacketList => 1,
        ActivePane::PacketTree => 2,
        ActivePane::HexDump => 3,
    };

    status_bar::render_status_bar(
        f,
        status_area,
        &app.source_name,
        app.packets.len(),
        filtered_packets.len(),
        selected_num,
        selected_len,
        active_pane_num,
        &app.theme,
        app.status_message.as_deref(),
    );

    // 4. Render Modals (Overlays)
    match &app.active_modal {
        ActiveModal::None => {}
        ActiveModal::Help => {
            modals::render_help_modal(f, f.area(), &app.theme);
        }
        ActiveModal::Conversations { active_tab, selected_idx } => {
            if let Some(convs) = &app.conversations {
                modals::render_convs_modal(f, f.area(), convs, *active_tab, *selected_idx, &app.theme);
            }
        }
        ActiveModal::FollowStream { stream, scroll_offset, hex_mode } => {
            modals::render_stream_modal(f, f.area(), stream, *scroll_offset, *hex_mode, &app.theme);
        }
        ActiveModal::Interfaces { list, selected_idx } => {
            modals::render_ifaces_modal(f, f.area(), list, *selected_idx, &app.theme);
        }
    }
}
