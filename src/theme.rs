#![allow(dead_code)]

use ratatui::style::{Color, Modifier, Style};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeVariant {
    DefaultDark,
    DefaultLight,
    Dracula,
    SolarizedDark,
    SolarizedLight,
    Base16,
}

impl Default for ThemeVariant {
    fn default() -> Self {
        ThemeVariant::DefaultDark
    }
}

impl ThemeVariant {
    pub fn from_name(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "light" | "default-light" => ThemeVariant::DefaultLight,
            "dracula" => ThemeVariant::Dracula,
            "solarized" | "solarized-dark" => ThemeVariant::SolarizedDark,
            "solarized-light" => ThemeVariant::SolarizedLight,
            "base16" => ThemeVariant::Base16,
            _ => ThemeVariant::DefaultDark,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Theme {
    pub variant: ThemeVariant,
    pub bg: Color,
    pub fg: Color,
    pub border: Color,
    pub border_focused: Color,
    pub header_fg: Color,
    pub header_bg: Color,

    // Packet list
    pub row_even: Color,
    pub row_odd: Color,
    pub row_selected_fg: Color,
    pub row_selected_bg: Color,
    pub row_marked_fg: Color,
    pub row_marked_bg: Color,

    // Protocols
    pub proto_tcp: Color,
    pub proto_udp: Color,
    pub proto_dns: Color,
    pub proto_http: Color,
    pub proto_icmp: Color,
    pub proto_arp: Color,
    pub proto_tls: Color,
    pub proto_other: Color,

    // Packet details / tree
    pub tree_fg: Color,
    pub tree_selected_fg: Color,
    pub tree_selected_bg: Color,
    pub tree_field_name: Color,
    pub tree_field_val: Color,

    // Hex dump
    pub hex_offset: Color,
    pub hex_byte: Color,
    pub hex_ascii: Color,
    pub hex_highlight_fg: Color,
    pub hex_highlight_bg: Color,
    pub hex_cursor_fg: Color,
    pub hex_cursor_bg: Color,

    // Filter bar
    pub filter_valid_fg: Color,
    pub filter_valid_bg: Color,
    pub filter_invalid_fg: Color,
    pub filter_invalid_bg: Color,
    pub filter_empty_fg: Color,
    pub filter_empty_bg: Color,

    // Status bar
    pub status_bg: Color,
    pub status_fg: Color,
    pub status_key_fg: Color,
    pub status_accent: Color,

    // Dialog / Modal
    pub modal_bg: Color,
    pub modal_fg: Color,
    pub modal_border: Color,
    pub modal_selected_fg: Color,
    pub modal_selected_bg: Color,

    // Stream
    pub stream_client: Color,
    pub stream_server: Color,
}

impl Theme {
    pub fn new(variant: ThemeVariant) -> Self {
        match variant {
            ThemeVariant::DefaultDark => Theme {
                variant,
                bg: Color::Reset,
                fg: Color::Rgb(220, 220, 220),
                border: Color::Rgb(80, 80, 90),
                border_focused: Color::Rgb(0, 180, 255),
                header_fg: Color::Rgb(255, 255, 255),
                header_bg: Color::Rgb(35, 45, 60),

                row_even: Color::Reset,
                row_odd: Color::Rgb(22, 25, 30),
                row_selected_fg: Color::Rgb(255, 255, 255),
                row_selected_bg: Color::Rgb(0, 95, 175),
                row_marked_fg: Color::Rgb(255, 230, 100),
                row_marked_bg: Color::Rgb(60, 40, 80),

                proto_tcp: Color::Rgb(130, 190, 255),
                proto_udp: Color::Rgb(150, 220, 150),
                proto_dns: Color::Rgb(255, 215, 120),
                proto_http: Color::Rgb(120, 230, 210),
                proto_icmp: Color::Rgb(255, 150, 150),
                proto_arp: Color::Rgb(240, 170, 230),
                proto_tls: Color::Rgb(200, 170, 255),
                proto_other: Color::Rgb(180, 180, 180),

                tree_fg: Color::Rgb(220, 220, 220),
                tree_selected_fg: Color::Rgb(255, 255, 255),
                tree_selected_bg: Color::Rgb(0, 95, 175),
                tree_field_name: Color::Rgb(120, 200, 255),
                tree_field_val: Color::Rgb(240, 240, 240),

                hex_offset: Color::Rgb(110, 120, 140),
                hex_byte: Color::Rgb(200, 200, 200),
                hex_ascii: Color::Rgb(170, 210, 180),
                hex_highlight_fg: Color::Rgb(255, 255, 255),
                hex_highlight_bg: Color::Rgb(0, 110, 210),
                hex_cursor_fg: Color::Rgb(0, 0, 0),
                hex_cursor_bg: Color::Rgb(255, 215, 0),

                filter_valid_fg: Color::Rgb(255, 255, 255),
                filter_valid_bg: Color::Rgb(20, 110, 50),
                filter_invalid_fg: Color::Rgb(255, 255, 255),
                filter_invalid_bg: Color::Rgb(150, 30, 30),
                filter_empty_fg: Color::Rgb(230, 230, 230),
                filter_empty_bg: Color::Rgb(30, 35, 45),

                status_bg: Color::Rgb(24, 28, 36),
                status_fg: Color::Rgb(190, 190, 200),
                status_key_fg: Color::Rgb(255, 215, 0),
                status_accent: Color::Rgb(0, 180, 255),

                modal_bg: Color::Rgb(20, 24, 32),
                modal_fg: Color::Rgb(230, 230, 230),
                modal_border: Color::Rgb(0, 180, 255),
                modal_selected_fg: Color::Rgb(255, 255, 255),
                modal_selected_bg: Color::Rgb(0, 95, 175),

                stream_client: Color::Rgb(100, 180, 255),
                stream_server: Color::Rgb(255, 130, 130),
            },
            ThemeVariant::Dracula => Theme {
                variant,
                bg: Color::Rgb(40, 42, 54),
                fg: Color::Rgb(248, 248, 242),
                border: Color::Rgb(98, 114, 164),
                border_focused: Color::Rgb(189, 147, 249),
                header_fg: Color::Rgb(248, 248, 242),
                header_bg: Color::Rgb(68, 71, 90),

                row_even: Color::Rgb(40, 42, 54),
                row_odd: Color::Rgb(48, 50, 64),
                row_selected_fg: Color::Rgb(248, 248, 242),
                row_selected_bg: Color::Rgb(98, 114, 164),
                row_marked_fg: Color::Rgb(241, 250, 140),
                row_marked_bg: Color::Rgb(75, 55, 95),

                proto_tcp: Color::Rgb(139, 233, 253),
                proto_udp: Color::Rgb(80, 250, 123),
                proto_dns: Color::Rgb(241, 250, 140),
                proto_http: Color::Rgb(255, 121, 198),
                proto_icmp: Color::Rgb(255, 85, 85),
                proto_arp: Color::Rgb(255, 184, 108),
                proto_tls: Color::Rgb(189, 147, 249),
                proto_other: Color::Rgb(170, 170, 170),

                tree_fg: Color::Rgb(248, 248, 242),
                tree_selected_fg: Color::Rgb(40, 42, 54),
                tree_selected_bg: Color::Rgb(139, 233, 253),
                tree_field_name: Color::Rgb(189, 147, 249),
                tree_field_val: Color::Rgb(248, 248, 242),

                hex_offset: Color::Rgb(98, 114, 164),
                hex_byte: Color::Rgb(248, 248, 242),
                hex_ascii: Color::Rgb(80, 250, 123),
                hex_highlight_fg: Color::Rgb(40, 42, 54),
                hex_highlight_bg: Color::Rgb(189, 147, 249),
                hex_cursor_fg: Color::Rgb(40, 42, 54),
                hex_cursor_bg: Color::Rgb(241, 250, 140),

                filter_valid_fg: Color::Rgb(40, 42, 54),
                filter_valid_bg: Color::Rgb(80, 250, 123),
                filter_invalid_fg: Color::Rgb(248, 248, 242),
                filter_invalid_bg: Color::Rgb(255, 85, 85),
                filter_empty_fg: Color::Rgb(248, 248, 242),
                filter_empty_bg: Color::Rgb(68, 71, 90),

                status_bg: Color::Rgb(30, 31, 41),
                status_fg: Color::Rgb(248, 248, 242),
                status_key_fg: Color::Rgb(241, 250, 140),
                status_accent: Color::Rgb(189, 147, 249),

                modal_bg: Color::Rgb(40, 42, 54),
                modal_fg: Color::Rgb(248, 248, 242),
                modal_border: Color::Rgb(189, 147, 249),
                modal_selected_fg: Color::Rgb(40, 42, 54),
                modal_selected_bg: Color::Rgb(139, 233, 253),

                stream_client: Color::Rgb(139, 233, 253),
                stream_server: Color::Rgb(255, 121, 198),
            },
            ThemeVariant::SolarizedDark => Theme {
                variant,
                bg: Color::Rgb(0, 43, 54),
                fg: Color::Rgb(131, 148, 150),
                border: Color::Rgb(88, 110, 117),
                border_focused: Color::Rgb(38, 139, 210),
                header_fg: Color::Rgb(238, 232, 213),
                header_bg: Color::Rgb(7, 54, 66),

                row_even: Color::Rgb(0, 43, 54),
                row_odd: Color::Rgb(4, 48, 60),
                row_selected_fg: Color::Rgb(253, 246, 227),
                row_selected_bg: Color::Rgb(38, 139, 210),
                row_marked_fg: Color::Rgb(181, 137, 0),
                row_marked_bg: Color::Rgb(7, 54, 66),

                proto_tcp: Color::Rgb(38, 139, 210),
                proto_udp: Color::Rgb(133, 153, 0),
                proto_dns: Color::Rgb(181, 137, 0),
                proto_http: Color::Rgb(42, 161, 152),
                proto_icmp: Color::Rgb(220, 50, 47),
                proto_arp: Color::Rgb(211, 54, 130),
                proto_tls: Color::Rgb(108, 113, 196),
                proto_other: Color::Rgb(147, 161, 161),

                tree_fg: Color::Rgb(147, 161, 161),
                tree_selected_fg: Color::Rgb(253, 246, 227),
                tree_selected_bg: Color::Rgb(38, 139, 210),
                tree_field_name: Color::Rgb(42, 161, 152),
                tree_field_val: Color::Rgb(238, 232, 213),

                hex_offset: Color::Rgb(88, 110, 117),
                hex_byte: Color::Rgb(147, 161, 161),
                hex_ascii: Color::Rgb(133, 153, 0),
                hex_highlight_fg: Color::Rgb(253, 246, 227),
                hex_highlight_bg: Color::Rgb(38, 139, 210),
                hex_cursor_fg: Color::Rgb(0, 43, 54),
                hex_cursor_bg: Color::Rgb(181, 137, 0),

                filter_valid_fg: Color::Rgb(253, 246, 227),
                filter_valid_bg: Color::Rgb(133, 153, 0),
                filter_invalid_fg: Color::Rgb(253, 246, 227),
                filter_invalid_bg: Color::Rgb(220, 50, 47),
                filter_empty_fg: Color::Rgb(147, 161, 161),
                filter_empty_bg: Color::Rgb(7, 54, 66),

                status_bg: Color::Rgb(7, 54, 66),
                status_fg: Color::Rgb(147, 161, 161),
                status_key_fg: Color::Rgb(181, 137, 0),
                status_accent: Color::Rgb(38, 139, 210),

                modal_bg: Color::Rgb(0, 43, 54),
                modal_fg: Color::Rgb(147, 161, 161),
                modal_border: Color::Rgb(38, 139, 210),
                modal_selected_fg: Color::Rgb(253, 246, 227),
                modal_selected_bg: Color::Rgb(38, 139, 210),

                stream_client: Color::Rgb(38, 139, 210),
                stream_server: Color::Rgb(220, 50, 47),
            },
            ThemeVariant::DefaultLight | ThemeVariant::SolarizedLight => Theme {
                variant,
                bg: Color::Rgb(250, 250, 250),
                fg: Color::Rgb(40, 40, 40),
                border: Color::Rgb(180, 180, 190),
                border_focused: Color::Rgb(0, 102, 204),
                header_fg: Color::Rgb(255, 255, 255),
                header_bg: Color::Rgb(60, 70, 85),

                row_even: Color::Rgb(255, 255, 255),
                row_odd: Color::Rgb(240, 243, 246),
                row_selected_fg: Color::Rgb(255, 255, 255),
                row_selected_bg: Color::Rgb(0, 102, 204),
                row_marked_fg: Color::Rgb(140, 80, 0),
                row_marked_bg: Color::Rgb(255, 240, 200),

                proto_tcp: Color::Rgb(0, 80, 180),
                proto_udp: Color::Rgb(0, 130, 50),
                proto_dns: Color::Rgb(160, 100, 0),
                proto_http: Color::Rgb(0, 120, 130),
                proto_icmp: Color::Rgb(180, 30, 30),
                proto_arp: Color::Rgb(140, 40, 140),
                proto_tls: Color::Rgb(90, 40, 160),
                proto_other: Color::Rgb(80, 80, 80),

                tree_fg: Color::Rgb(40, 40, 40),
                tree_selected_fg: Color::Rgb(255, 255, 255),
                tree_selected_bg: Color::Rgb(0, 102, 204),
                tree_field_name: Color::Rgb(0, 90, 160),
                tree_field_val: Color::Rgb(20, 20, 20),

                hex_offset: Color::Rgb(120, 120, 120),
                hex_byte: Color::Rgb(30, 30, 30),
                hex_ascii: Color::Rgb(0, 110, 40),
                hex_highlight_fg: Color::Rgb(255, 255, 255),
                hex_highlight_bg: Color::Rgb(0, 102, 204),
                hex_cursor_fg: Color::Rgb(255, 255, 255),
                hex_cursor_bg: Color::Rgb(200, 120, 0),

                filter_valid_fg: Color::Rgb(255, 255, 255),
                filter_valid_bg: Color::Rgb(30, 140, 60),
                filter_invalid_fg: Color::Rgb(255, 255, 255),
                filter_invalid_bg: Color::Rgb(200, 40, 40),
                filter_empty_fg: Color::Rgb(40, 40, 40),
                filter_empty_bg: Color::Rgb(230, 235, 240),

                status_bg: Color::Rgb(230, 235, 240),
                status_fg: Color::Rgb(40, 40, 40),
                status_key_fg: Color::Rgb(160, 90, 0),
                status_accent: Color::Rgb(0, 102, 204),

                modal_bg: Color::Rgb(250, 250, 250),
                modal_fg: Color::Rgb(40, 40, 40),
                modal_border: Color::Rgb(0, 102, 204),
                modal_selected_fg: Color::Rgb(255, 255, 255),
                modal_selected_bg: Color::Rgb(0, 102, 204),

                stream_client: Color::Rgb(0, 90, 180),
                stream_server: Color::Rgb(180, 30, 30),
            },
            ThemeVariant::Base16 => Theme {
                variant,
                bg: Color::Rgb(24, 24, 24),
                fg: Color::Rgb(216, 216, 216),
                border: Color::Rgb(88, 88, 88),
                border_focused: Color::Rgb(124, 175, 194),
                header_fg: Color::Rgb(248, 248, 248),
                header_bg: Color::Rgb(40, 40, 40),

                row_even: Color::Rgb(24, 24, 24),
                row_odd: Color::Rgb(32, 32, 32),
                row_selected_fg: Color::Rgb(248, 248, 248),
                row_selected_bg: Color::Rgb(56, 56, 56),
                row_marked_fg: Color::Rgb(220, 150, 86),
                row_marked_bg: Color::Rgb(48, 48, 48),

                proto_tcp: Color::Rgb(124, 175, 194),
                proto_udp: Color::Rgb(144, 169, 89),
                proto_dns: Color::Rgb(247, 202, 136),
                proto_http: Color::Rgb(138, 190, 183),
                proto_icmp: Color::Rgb(171, 70, 66),
                proto_arp: Color::Rgb(186, 139, 175),
                proto_tls: Color::Rgb(161, 110, 165),
                proto_other: Color::Rgb(184, 184, 184),

                tree_fg: Color::Rgb(216, 216, 216),
                tree_selected_fg: Color::Rgb(248, 248, 248),
                tree_selected_bg: Color::Rgb(56, 56, 56),
                tree_field_name: Color::Rgb(124, 175, 194),
                tree_field_val: Color::Rgb(216, 216, 216),

                hex_offset: Color::Rgb(116, 116, 116),
                hex_byte: Color::Rgb(216, 216, 216),
                hex_ascii: Color::Rgb(144, 169, 89),
                hex_highlight_fg: Color::Rgb(24, 24, 24),
                hex_highlight_bg: Color::Rgb(124, 175, 194),
                hex_cursor_fg: Color::Rgb(24, 24, 24),
                hex_cursor_bg: Color::Rgb(247, 202, 136),

                filter_valid_fg: Color::Rgb(24, 24, 24),
                filter_valid_bg: Color::Rgb(144, 169, 89),
                filter_invalid_fg: Color::Rgb(248, 248, 248),
                filter_invalid_bg: Color::Rgb(171, 70, 66),
                filter_empty_fg: Color::Rgb(216, 216, 216),
                filter_empty_bg: Color::Rgb(40, 40, 40),

                status_bg: Color::Rgb(40, 40, 40),
                status_fg: Color::Rgb(216, 216, 216),
                status_key_fg: Color::Rgb(247, 202, 136),
                status_accent: Color::Rgb(124, 175, 194),

                modal_bg: Color::Rgb(24, 24, 24),
                modal_fg: Color::Rgb(216, 216, 216),
                modal_border: Color::Rgb(124, 175, 194),
                modal_selected_fg: Color::Rgb(248, 248, 248),
                modal_selected_bg: Color::Rgb(56, 56, 56),

                stream_client: Color::Rgb(124, 175, 194),
                stream_server: Color::Rgb(171, 70, 66),
            },
        }
    }

    pub fn proto_color(&self, proto: &str) -> Color {
        match proto.to_uppercase().as_str() {
            "TCP" => self.proto_tcp,
            "UDP" => self.proto_udp,
            "DNS" => self.proto_dns,
            "HTTP" | "HTTPS" => self.proto_http,
            "ICMP" | "ICMPV6" => self.proto_icmp,
            "ARP" => self.proto_arp,
            "TLS" | "SSL" => self.proto_tls,
            _ => self.proto_other,
        }
    }

    pub fn style_base(&self) -> Style {
        Style::default().bg(self.bg).fg(self.fg)
    }

    pub fn style_border(&self, focused: bool) -> Style {
        if focused {
            Style::default().fg(self.border_focused).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(self.border)
        }
    }
}
