use crate::capture::{list_interfaces, InterfaceInfo};
use crate::packet::convs::{ConvType, Conversations};
use crate::packet::filter::FilterExpr;
use crate::packet::stream::StreamReassembly;
use crate::packet::PacketRecord;
use crate::theme::{Theme, ThemeVariant};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivePane {
    PacketList,
    PacketTree,
    HexDump,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutMode {
    VerticalStack,
    SideBySide,
}

#[derive(Debug, Clone)]
pub enum ActiveModal {
    None,
    Help,
    Conversations { active_tab: ConvType, selected_idx: usize },
    FollowStream { stream: StreamReassembly, scroll_offset: usize, hex_mode: bool },
    Interfaces { list: Vec<InterfaceInfo>, selected_idx: usize },
}

pub struct App {
    pub packets: Vec<PacketRecord>,
    pub filtered_indices: Vec<usize>,
    pub source_name: String,
    pub theme: Theme,

    // Filter
    pub filter_input: String,
    pub filter_cursor_pos: usize,
    pub is_filter_focused: bool,
    pub is_filter_valid: bool,
    pub filter_history: Vec<String>,

    // Panes & Layout
    pub active_pane: ActivePane,
    pub maximized_pane: Option<ActivePane>,
    pub layout_mode: LayoutMode,
    pub pane_list_pct: u16,
    pub pane_tree_pct: u16,
    pub pane_hex_pct: u16,

    // Selections and offsets
    pub packet_list_selected_idx: usize,
    pub packet_list_scroll_offset: usize,
    pub tree_selected_row: usize,
    pub tree_scroll_offset: usize,
    pub hex_scroll_offset: usize,
    pub hex_cursor_byte: Option<usize>,

    // Sorting
    pub sort_column: usize,
    pub sort_desc: bool,

    // Marks
    pub marks: HashMap<char, usize>,
    pub last_jump_packet: Option<usize>,
    pub pending_mark: bool,
    pub pending_jump: bool,

    // Dialogs
    pub active_modal: ActiveModal,
    pub conversations: Option<Conversations>,

    // Status feedback
    pub status_message: Option<String>,
}

impl App {
    pub fn new(source_name: String, packets: Vec<PacketRecord>, theme_variant: ThemeVariant) -> Self {
        let n_pkts = packets.len();
        let filtered_indices: Vec<usize> = (0..n_pkts).collect();
        let convs = Conversations::build(&packets);

        Self {
            packets,
            filtered_indices,
            source_name,
            theme: Theme::new(theme_variant),

            filter_input: String::new(),
            filter_cursor_pos: 0,
            is_filter_focused: false,
            is_filter_valid: true,
            filter_history: Vec::new(),

            active_pane: ActivePane::PacketList,
            maximized_pane: None,
            layout_mode: LayoutMode::VerticalStack,
            pane_list_pct: 40,
            pane_tree_pct: 30,
            pane_hex_pct: 30,

            packet_list_selected_idx: 0,
            packet_list_scroll_offset: 0,
            tree_selected_row: 0,
            tree_scroll_offset: 0,
            hex_scroll_offset: 0,
            hex_cursor_byte: None,

            sort_column: 0,
            sort_desc: false,

            marks: HashMap::new(),
            last_jump_packet: None,
            pending_mark: false,
            pending_jump: false,

            active_modal: ActiveModal::None,
            conversations: Some(convs),

            status_message: None,
        }
    }

    pub fn add_packet(&mut self, pkt: PacketRecord) {
        let is_matching = if self.filter_input.trim().is_empty() {
            true
        } else if let Ok(expr) = FilterExpr::parse(&self.filter_input) {
            expr.matches(&pkt)
        } else {
            true
        };

        let new_idx = self.packets.len();
        self.packets.push(pkt);
        if is_matching {
            self.filtered_indices.push(new_idx);
        }
    }

    pub fn filtered_packet_refs(&self) -> Vec<&PacketRecord> {
        self.filtered_indices
            .iter()
            .filter_map(|&i| self.packets.get(i))
            .collect()
    }

    pub fn current_packet(&self) -> Option<&PacketRecord> {
        let global_idx = *self.filtered_indices.get(self.packet_list_selected_idx)?;
        self.packets.get(global_idx)
    }

    pub fn current_packet_mut(&mut self) -> Option<&mut PacketRecord> {
        let global_idx = *self.filtered_indices.get(self.packet_list_selected_idx)?;
        self.packets.get_mut(global_idx)
    }

    pub fn apply_filter(&mut self) {
        let trimmed = self.filter_input.trim();
        if trimmed.is_empty() {
            self.filtered_indices = (0..self.packets.len()).collect();
            self.is_filter_valid = true;
            self.packet_list_selected_idx = 0;
            self.packet_list_scroll_offset = 0;
            self.tree_selected_row = 0;
            self.status_message = Some(format!("Filter cleared ({} packets)", self.packets.len()));
            return;
        }

        match FilterExpr::parse(trimmed) {
            Ok(expr) => {
                self.is_filter_valid = true;
                self.filtered_indices = self
                    .packets
                    .iter()
                    .enumerate()
                    .filter(|(_, pkt)| expr.matches(pkt))
                    .map(|(idx, _)| idx)
                    .collect();

                self.packet_list_selected_idx = 0;
                self.packet_list_scroll_offset = 0;
                self.tree_selected_row = 0;

                if !self.filter_history.contains(&trimmed.to_string()) {
                    self.filter_history.push(trimmed.to_string());
                }

                self.status_message = Some(format!(
                    "Filter matched {} of {} packets",
                    self.filtered_indices.len(),
                    self.packets.len()
                ));
            }
            Err(e) => {
                self.is_filter_valid = false;
                self.status_message = Some(format!("Invalid filter: {}", e));
            }
        }
    }

    pub fn validate_filter_live(&mut self) {
        let trimmed = self.filter_input.trim();
        self.is_filter_valid = trimmed.is_empty() || FilterExpr::parse(trimmed).is_ok();
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        // 1. If mark or jump is pending
        if self.pending_mark {
            self.pending_mark = false;
            if let KeyCode::Char(c) = key.code {
                if c.is_ascii_alphabetic() {
                    self.marks.insert(c, self.packet_list_selected_idx);
                    self.status_message = Some(format!("Mark '{}' set on packet {}", c, self.packet_list_selected_idx + 1));
                }
            }
            return true;
        }

        if self.pending_jump {
            self.pending_jump = false;
            if let KeyCode::Char(c) = key.code {
                if c == '\'' {
                    // Jump to previous position
                    if let Some(prev) = self.last_jump_packet {
                        self.packet_list_selected_idx = prev.min(self.filtered_indices.len().saturating_sub(1));
                        self.status_message = Some("Jumped to previous packet".to_string());
                    }
                } else if let Some(&target_idx) = self.marks.get(&c) {
                    self.last_jump_packet = Some(self.packet_list_selected_idx);
                    self.packet_list_selected_idx = target_idx.min(self.filtered_indices.len().saturating_sub(1));
                    self.adjust_packet_list_scroll();
                    self.status_message = Some(format!("Jumped to mark '{}'", c));
                }
            }
            return true;
        }

        // 2. If Modal is active
        if !matches!(self.active_modal, ActiveModal::None) {
            return self.handle_modal_key(key);
        }

        // 3. If Filter input is focused
        if self.is_filter_focused {
            return self.handle_filter_input_key(key);
        }

        // 4. Main App Keybindings
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return false,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return false,

            // Focus display filter
            KeyCode::Char('/') => {
                self.is_filter_focused = true;
                self.filter_cursor_pos = self.filter_input.len();
            }

            // Pane switching
            KeyCode::Tab => {
                self.active_pane = match self.active_pane {
                    ActivePane::PacketList => ActivePane::PacketTree,
                    ActivePane::PacketTree => ActivePane::HexDump,
                    ActivePane::HexDump => ActivePane::PacketList,
                };
            }
            KeyCode::BackTab => {
                self.active_pane = match self.active_pane {
                    ActivePane::PacketList => ActivePane::HexDump,
                    ActivePane::PacketTree => ActivePane::PacketList,
                    ActivePane::HexDump => ActivePane::PacketTree,
                };
            }
            KeyCode::Char('1') => self.active_pane = ActivePane::PacketList,
            KeyCode::Char('2') => self.active_pane = ActivePane::PacketTree,
            KeyCode::Char('3') => self.active_pane = ActivePane::HexDump,

            // Maximize pane toggle
            KeyCode::Char('\\') => {
                if self.maximized_pane.is_some() {
                    self.maximized_pane = None;
                } else {
                    self.maximized_pane = Some(self.active_pane);
                }
            }

            // Layout toggle: vertical stack vs side-by-side
            KeyCode::Char('|') => {
                self.layout_mode = match self.layout_mode {
                    LayoutMode::VerticalStack => LayoutMode::SideBySide,
                    LayoutMode::SideBySide => LayoutMode::VerticalStack,
                };
            }

            // Pane resizing
            KeyCode::Char('+') => {
                if self.pane_list_pct < 70 {
                    self.pane_list_pct += 5;
                    self.pane_tree_pct = self.pane_tree_pct.saturating_sub(2);
                    self.pane_hex_pct = self.pane_hex_pct.saturating_sub(3);
                }
            }
            KeyCode::Char('-') => {
                if self.pane_list_pct > 20 {
                    self.pane_list_pct -= 5;
                    self.pane_tree_pct += 2;
                    self.pane_hex_pct += 3;
                }
            }

            // Modals
            KeyCode::Char('?') | KeyCode::F(1) => {
                self.active_modal = ActiveModal::Help;
            }
            KeyCode::Char('c') => {
                self.conversations = Some(Conversations::build(&self.packets));
                self.active_modal = ActiveModal::Conversations {
                    active_tab: ConvType::Ethernet,
                    selected_idx: 0,
                };
            }
            KeyCode::Char('s') => {
                if let Some(target) = self.current_packet() {
                    if let Some(stream) = StreamReassembly::reassemble_for_packet(target, &self.packets) {
                        self.active_modal = ActiveModal::FollowStream {
                            stream,
                            scroll_offset: 0,
                            hex_mode: false,
                        };
                    } else {
                        self.status_message = Some("No stream data found for selected packet".to_string());
                    }
                }
            }
            KeyCode::Char('p') => {
                let ifaces = list_interfaces();
                self.active_modal = ActiveModal::Interfaces {
                    list: ifaces,
                    selected_idx: 0,
                };
            }

            // Theme cycling
            KeyCode::Char('t') => {
                let next_variant = match self.theme.variant {
                    ThemeVariant::DefaultDark => ThemeVariant::Dracula,
                    ThemeVariant::Dracula => ThemeVariant::SolarizedDark,
                    ThemeVariant::SolarizedDark => ThemeVariant::DefaultLight,
                    ThemeVariant::DefaultLight => ThemeVariant::Base16,
                    ThemeVariant::Base16 => ThemeVariant::DefaultDark,
                    _ => ThemeVariant::DefaultDark,
                };
                self.theme = Theme::new(next_variant);
                self.status_message = Some(format!("Theme: {:?}", next_variant));
            }

            // Marks
            KeyCode::Char('m') => {
                self.pending_mark = true;
                self.status_message = Some("Set mark: press a-z...".to_string());
            }
            KeyCode::Char('\'') => {
                self.pending_jump = true;
                self.status_message = Some("Jump to mark: press a-z or '...".to_string());
            }

            // Sorting
            KeyCode::Char('o') => {
                self.sort_column = (self.sort_column + 1) % 7;
                self.sort_packets();
            }

            // Navigation per active pane
            _ => match self.active_pane {
                ActivePane::PacketList => self.handle_packet_list_key(key),
                ActivePane::PacketTree => self.handle_packet_tree_key(key),
                ActivePane::HexDump => self.handle_hex_dump_key(key),
            },
        }

        true
    }

    fn handle_filter_input_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Enter => {
                self.is_filter_focused = false;
                self.apply_filter();
            }
            KeyCode::Esc => {
                self.is_filter_focused = false;
                self.filter_input.clear();
                self.filter_cursor_pos = 0;
                self.apply_filter();
            }
            KeyCode::Char(c) => {
                self.filter_input.insert(self.filter_cursor_pos, c);
                self.filter_cursor_pos += 1;
                self.validate_filter_live();
            }
            KeyCode::Backspace => {
                if self.filter_cursor_pos > 0 {
                    self.filter_cursor_pos -= 1;
                    self.filter_input.remove(self.filter_cursor_pos);
                    self.validate_filter_live();
                }
            }
            KeyCode::Delete => {
                if self.filter_cursor_pos < self.filter_input.len() {
                    self.filter_input.remove(self.filter_cursor_pos);
                    self.validate_filter_live();
                }
            }
            KeyCode::Left => {
                if self.filter_cursor_pos > 0 {
                    self.filter_cursor_pos -= 1;
                }
            }
            KeyCode::Right => {
                if self.filter_cursor_pos < self.filter_input.len() {
                    self.filter_cursor_pos += 1;
                }
            }
            KeyCode::Home => self.filter_cursor_pos = 0,
            KeyCode::End => self.filter_cursor_pos = self.filter_input.len(),
            _ => {}
        }
        true
    }

    fn handle_packet_list_key(&mut self, key: KeyEvent) {
        let n_items = self.filtered_indices.len();
        if n_items == 0 {
            return;
        }

        match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                if self.packet_list_selected_idx + 1 < n_items {
                    self.packet_list_selected_idx += 1;
                    self.adjust_packet_list_scroll();
                    self.tree_selected_row = 0;
                    self.tree_scroll_offset = 0;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.packet_list_selected_idx > 0 {
                    self.packet_list_selected_idx -= 1;
                    self.adjust_packet_list_scroll();
                    self.tree_selected_row = 0;
                    self.tree_scroll_offset = 0;
                }
            }
            KeyCode::PageDown => {
                self.packet_list_selected_idx = (self.packet_list_selected_idx + 15).min(n_items - 1);
                self.adjust_packet_list_scroll();
                self.tree_selected_row = 0;
            }
            KeyCode::PageUp => {
                self.packet_list_selected_idx = self.packet_list_selected_idx.saturating_sub(15);
                self.adjust_packet_list_scroll();
                self.tree_selected_row = 0;
            }
            KeyCode::Home | KeyCode::Char('g') => {
                self.packet_list_selected_idx = 0;
                self.adjust_packet_list_scroll();
                self.tree_selected_row = 0;
            }
            KeyCode::End | KeyCode::Char('G') => {
                self.packet_list_selected_idx = n_items.saturating_sub(1);
                self.adjust_packet_list_scroll();
                self.tree_selected_row = 0;
            }
            _ => {}
        }
    }

    fn handle_packet_tree_key(&mut self, key: KeyEvent) {
        let visible_count = self
            .current_packet()
            .map(|p| p.tree.visible_nodes().len())
            .unwrap_or(0);

        if visible_count == 0 {
            return;
        }

        match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                if self.tree_selected_row + 1 < visible_count {
                    self.tree_selected_row += 1;
                    if self.tree_selected_row >= self.tree_scroll_offset + 15 {
                        self.tree_scroll_offset += 1;
                    }
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.tree_selected_row > 0 {
                    self.tree_selected_row -= 1;
                    if self.tree_selected_row < self.tree_scroll_offset {
                        self.tree_scroll_offset = self.tree_selected_row;
                    }
                }
            }
            KeyCode::Enter | KeyCode::Char(' ') | KeyCode::Right => {
                // Toggle expand/collapse on the selected node
                let path = {
                    let pkt = match self.current_packet() {
                        Some(p) => p,
                        None => return,
                    };
                    let nodes = pkt.tree.visible_nodes();
                    nodes.get(self.tree_selected_row).map(|(p, _, _)| p.clone())
                };

                if let Some(path) = path {
                    if let Some(pkt) = self.current_packet_mut() {
                        if let Some(node) = pkt.tree.get_node_mut(&path) {
                            node.expanded = !node.expanded;
                        }
                    }
                }
            }
            KeyCode::Left => {
                // Collapse node
                let path = {
                    let pkt = match self.current_packet() {
                        Some(p) => p,
                        None => return,
                    };
                    let nodes = pkt.tree.visible_nodes();
                    nodes.get(self.tree_selected_row).map(|(p, _, _)| p.clone())
                };

                if let Some(path) = path {
                    if let Some(pkt) = self.current_packet_mut() {
                        if let Some(node) = pkt.tree.get_node_mut(&path) {
                            node.expanded = false;
                        }
                    }
                }
            }
            KeyCode::Char('e') => {
                // Expand all
                if let Some(pkt) = self.current_packet_mut() {
                    pkt.tree.set_all_expanded(true);
                }
            }
            KeyCode::Char('c') => {
                // Collapse all
                if let Some(pkt) = self.current_packet_mut() {
                    pkt.tree.set_all_expanded(false);
                }
            }
            _ => {}
        }
    }

    fn handle_hex_dump_key(&mut self, key: KeyEvent) {
        let total_bytes = self.current_packet().map(|p| p.raw_data.len()).unwrap_or(0);
        let total_lines = (total_bytes + 15) / 16;

        match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                if self.hex_scroll_offset + 1 < total_lines {
                    self.hex_scroll_offset += 1;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.hex_scroll_offset > 0 {
                    self.hex_scroll_offset -= 1;
                }
            }
            KeyCode::PageDown => {
                self.hex_scroll_offset = (self.hex_scroll_offset + 10).min(total_lines.saturating_sub(1));
            }
            KeyCode::PageUp => {
                self.hex_scroll_offset = self.hex_scroll_offset.saturating_sub(10);
            }
            KeyCode::Home | KeyCode::Char('g') => self.hex_scroll_offset = 0,
            KeyCode::End | KeyCode::Char('G') => self.hex_scroll_offset = total_lines.saturating_sub(5),
            KeyCode::Char('y') => {
                // Copy byte data summary
                self.status_message = Some(format!("Copied {} bytes of packet data", total_bytes));
            }
            _ => {}
        }
    }

    fn handle_modal_key(&mut self, key: KeyEvent) -> bool {
        match &mut self.active_modal {
            ActiveModal::Help => {
                if matches!(key.code, KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?')) {
                    self.active_modal = ActiveModal::None;
                }
            }
            ActiveModal::Conversations { active_tab, selected_idx } => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => self.active_modal = ActiveModal::None,
                KeyCode::Tab | KeyCode::Right => {
                    *active_tab = match *active_tab {
                        ConvType::Ethernet => ConvType::IPv4,
                        ConvType::IPv4 => ConvType::IPv6,
                        ConvType::IPv6 => ConvType::TCP,
                        ConvType::TCP => ConvType::UDP,
                        ConvType::UDP => ConvType::Ethernet,
                    };
                    *selected_idx = 0;
                }
                KeyCode::BackTab | KeyCode::Left => {
                    *active_tab = match *active_tab {
                        ConvType::Ethernet => ConvType::UDP,
                        ConvType::IPv4 => ConvType::Ethernet,
                        ConvType::IPv6 => ConvType::IPv4,
                        ConvType::TCP => ConvType::IPv6,
                        ConvType::UDP => ConvType::TCP,
                    };
                    *selected_idx = 0;
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    *selected_idx += 1;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    if *selected_idx > 0 {
                        *selected_idx -= 1;
                    }
                }
                KeyCode::Enter => {
                    // Apply conversation filter!
                    if let Some(convs) = &self.conversations {
                        let list = match *active_tab {
                            ConvType::Ethernet => &convs.eth_convs,
                            ConvType::IPv4 => &convs.ip4_convs,
                            ConvType::IPv6 => &convs.ip6_convs,
                            ConvType::TCP => &convs.tcp_convs,
                            ConvType::UDP => &convs.udp_convs,
                        };
                        if let Some(row) = list.get(*selected_idx) {
                            let filter_str = row.to_filter(*active_tab);
                            self.filter_input = filter_str;
                            self.apply_filter();
                            self.active_modal = ActiveModal::None;
                        }
                    }
                }
                _ => {}
            },
            ActiveModal::FollowStream { scroll_offset, hex_mode, .. } => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => self.active_modal = ActiveModal::None,
                KeyCode::Char('h') => *hex_mode = !*hex_mode,
                KeyCode::Down | KeyCode::Char('j') => *scroll_offset += 1,
                KeyCode::Up | KeyCode::Char('k') => *scroll_offset = scroll_offset.saturating_sub(1),
                KeyCode::PageDown => *scroll_offset += 15,
                KeyCode::PageUp => *scroll_offset = scroll_offset.saturating_sub(15),
                _ => {}
            },
            ActiveModal::Interfaces { list, selected_idx } => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => self.active_modal = ActiveModal::None,
                KeyCode::Down | KeyCode::Char('j') => {
                    if *selected_idx + 1 < list.len() {
                        *selected_idx += 1;
                    }
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    if *selected_idx > 0 {
                        *selected_idx -= 1;
                    }
                }
                KeyCode::Enter => {
                    if let Some(iface) = list.get(*selected_idx) {
                        self.status_message = Some(format!("Selected interface: {}", iface.name));
                        self.active_modal = ActiveModal::None;
                    }
                }
                _ => {}
            },
            ActiveModal::None => {}
        }
        true
    }

    fn adjust_packet_list_scroll(&mut self) {
        if self.packet_list_selected_idx < self.packet_list_scroll_offset {
            self.packet_list_scroll_offset = self.packet_list_selected_idx;
        } else if self.packet_list_selected_idx >= self.packet_list_scroll_offset + 15 {
            self.packet_list_scroll_offset = self.packet_list_selected_idx.saturating_sub(14);
        }
    }

    fn sort_packets(&mut self) {
        let col = self.sort_column;
        let desc = self.sort_desc;
        let packets = &self.packets;

        self.filtered_indices.sort_by(|&a, &b| {
            let pa = &packets[a];
            let pb = &packets[b];
            let cmp = match col {
                0 => pa.summary.num.cmp(&pb.summary.num),
                1 => pa.summary.rel_time_secs.partial_cmp(&pb.summary.rel_time_secs).unwrap(),
                2 => pa.summary.src.cmp(&pb.summary.src),
                3 => pa.summary.dst.cmp(&pb.summary.dst),
                4 => pa.summary.protocol.cmp(&pb.summary.protocol),
                5 => pa.summary.length.cmp(&pb.summary.length),
                6 => pa.summary.info.cmp(&pb.summary.info),
                _ => std::cmp::Ordering::Equal,
            };
            if desc {
                cmp.reverse()
            } else {
                cmp
            }
        });

        self.packet_list_selected_idx = 0;
        self.packet_list_scroll_offset = 0;
    }
}
