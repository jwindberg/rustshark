#![allow(unused_assignments)]

use super::{DissectionTree, PacketRecord, PacketSummary, TreeNode};
use std::net::{Ipv4Addr, Ipv6Addr};

pub struct PacketDissector;

impl PacketDissector {
    pub fn dissect(
        num: usize,
        rel_time_secs: f64,
        ts_secs: u64,
        ts_nanos: u32,
        data: &[u8],
        link_type: u32, // 1 = Ethernet, 113 = Linux SLL, 12 = Raw IP, etc.
    ) -> PacketRecord {
        let mut tree = DissectionTree::new();
        let total_len = data.len();

        // 1. Frame
        let mut frame_node = TreeNode::new(format!("Frame {}: {} bytes on wire", num, total_len))
            .with_range(0..total_len)
            .with_field("frame.len", total_len.to_string())
            .with_expanded(true);
        frame_node.add_child(
            TreeNode::new(format!("Frame Number: {}", num))
                .with_range(0..total_len)
                .with_field("frame.number", num.to_string()),
        );
        frame_node.add_child(
            TreeNode::new(format!("Frame Length: {} bytes", total_len))
                .with_range(0..total_len)
                .with_field("frame.len", total_len.to_string()),
        );
        frame_node.add_child(
            TreeNode::new(format!("Time: {:.6} seconds", rel_time_secs))
                .with_range(0..total_len)
                .with_field("frame.time_relative", format!("{:.6}", rel_time_secs)),
        );

        let mut offset = 0;
        let mut src_str = String::from("Unknown");
        let mut dst_str = String::from("Unknown");
        let mut protocol = String::from("Raw");
        let mut info = format!("Length: {} bytes", total_len);

        // 2. Link Layer Dissection
        let mut network_offset = 0;
        let mut ether_type = 0u16;

        if link_type == 113 && data.len() >= 16 {
            // Linux Cooked Capture (SLL)
            let packet_type = u16::from_be_bytes([data[0], data[1]]);
            let arphdr = u16::from_be_bytes([data[2], data[3]]);
            let addr_len = u16::from_be_bytes([data[4], data[5]]);
            ether_type = u16::from_be_bytes([data[14], data[15]]);
            network_offset = 16;

            let mut sll_node = TreeNode::new(format!("Linux cooked capture v1, Type: {}", packet_type))
                .with_range(0..16)
                .with_field("sll", "")
                .with_expanded(true);
            sll_node.add_child(
                TreeNode::new(format!("Packet type: {}", packet_type))
                    .with_range(0..2)
                    .with_field("sll.pkttype", packet_type.to_string()),
            );
            sll_node.add_child(
                TreeNode::new(format!("Link-layer address type: {}", arphdr))
                    .with_range(2..4)
                    .with_field("sll.hatype", arphdr.to_string()),
            );
            sll_node.add_child(
                TreeNode::new(format!("Link-layer address length: {}", addr_len))
                    .with_range(4..6)
                    .with_field("sll.halen", addr_len.to_string()),
            );
            sll_node.add_child(
                TreeNode::new(format!("Protocol: 0x{:04x}", ether_type))
                    .with_range(14..16)
                    .with_field("sll.etype", format!("0x{:04x}", ether_type)),
            );
            tree.add_root(frame_node);
            tree.add_root(sll_node);
        } else if data.len() >= 14 {
            // Standard Ethernet II
            let dst_mac = format_mac(&data[0..6]);
            let src_mac = format_mac(&data[6..12]);
            ether_type = u16::from_be_bytes([data[12], data[13]]);
            network_offset = 14;

            src_str = src_mac.clone();
            dst_str = dst_mac.clone();

            let type_desc = match ether_type {
                0x0800 => "IPv4 (0x0800)",
                0x86dd => "IPv6 (0x86dd)",
                0x0806 => "ARP (0x0806)",
                0x8100 => "802.1Q VLAN (0x8100)",
                _ => "Unknown",
            };

            let mut eth_node = TreeNode::new(format!("Ethernet II, Src: {}, Dst: {}", src_mac, dst_mac))
                .with_range(0..14)
                .with_field("eth", "")
                .with_expanded(true);
            eth_node.add_child(
                TreeNode::new(format!("Destination: {}", dst_mac))
                    .with_range(0..6)
                    .with_field("eth.dst", dst_mac),
            );
            eth_node.add_child(
                TreeNode::new(format!("Source: {}", src_mac))
                    .with_range(6..12)
                    .with_field("eth.src", src_mac),
            );
            eth_node.add_child(
                TreeNode::new(format!("Type: {}", type_desc))
                    .with_range(12..14)
                    .with_field("eth.type", format!("0x{:04x}", ether_type)),
            );
            tree.add_root(frame_node);
            tree.add_root(eth_node);
        } else {
            tree.add_root(frame_node);
        }

        offset = network_offset;

        // 3. Network Layer Dissection
        let mut transport_offset = offset;
        let mut ip_proto = 0u8;

        if ether_type == 0x0800 && data.len() >= offset + 20 {
            // IPv4
            let ip_bytes = &data[offset..];
            let version = ip_bytes[0] >> 4;
            let ihl = (ip_bytes[0] & 0x0f) as usize * 4;
            let dscp = ip_bytes[1] >> 2;
            let total_len = u16::from_be_bytes([ip_bytes[2], ip_bytes[3]]) as usize;
            let id = u16::from_be_bytes([ip_bytes[4], ip_bytes[5]]);
            let flags_raw = ip_bytes[6] >> 5;
            let df = (flags_raw & 0x02) != 0;
            let mf = (flags_raw & 0x01) != 0;
            let _frag_offset = (u16::from_be_bytes([ip_bytes[6] & 0x1f, ip_bytes[7]]) * 8) as usize;
            let ttl = ip_bytes[8];
            ip_proto = ip_bytes[9];
            let checksum = u16::from_be_bytes([ip_bytes[10], ip_bytes[11]]);
            let src_ip = Ipv4Addr::new(ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]);
            let dst_ip = Ipv4Addr::new(ip_bytes[16], ip_bytes[17], ip_bytes[18], ip_bytes[19]);

            src_str = src_ip.to_string();
            dst_str = dst_ip.to_string();
            transport_offset = offset + ihl;

            let proto_desc = match ip_proto {
                1 => "ICMP (1)",
                6 => "TCP (6)",
                17 => "UDP (17)",
                _ => "Other",
            };

            let mut ip_node = TreeNode::new(format!(
                "Internet Protocol Version 4, Src: {}, Dst: {}",
                src_ip, dst_ip
            ))
            .with_range(offset..(offset + ihl))
            .with_field("ip", "")
            .with_expanded(true);

            ip_node.add_child(
                TreeNode::new(format!("Version: {}", version))
                    .with_range(offset..offset + 1)
                    .with_field("ip.version", version.to_string()),
            );
            ip_node.add_child(
                TreeNode::new(format!("Header Length: {} bytes ({})", ihl, ihl / 4))
                    .with_range(offset..offset + 1)
                    .with_field("ip.hdr_len", ihl.to_string()),
            );
            ip_node.add_child(
                TreeNode::new(format!("Differentiated Services Field: 0x{:02x} (DSCP: {})", ip_bytes[1], dscp))
                    .with_range(offset + 1..offset + 2)
                    .with_field("ip.dsfield", format!("0x{:02x}", ip_bytes[1])),
            );
            ip_node.add_child(
                TreeNode::new(format!("Total Length: {}", total_len))
                    .with_range(offset + 2..offset + 4)
                    .with_field("ip.len", total_len.to_string()),
            );
            ip_node.add_child(
                TreeNode::new(format!("Identification: 0x{:04x} ({})", id, id))
                    .with_range(offset + 4..offset + 6)
                    .with_field("ip.id", format!("0x{:04x}", id)),
            );
            ip_node.add_child(
                TreeNode::new(format!("Flags: 0x{:02x} (DF: {}, MF: {})", flags_raw, df, mf))
                    .with_range(offset + 6..offset + 7)
                    .with_field("ip.flags", format!("0x{:02x}", flags_raw)),
            );
            ip_node.add_child(
                TreeNode::new(format!("Time to Live: {}", ttl))
                    .with_range(offset + 8..offset + 9)
                    .with_field("ip.ttl", ttl.to_string()),
            );
            ip_node.add_child(
                TreeNode::new(format!("Protocol: {}", proto_desc))
                    .with_range(offset + 9..offset + 10)
                    .with_field("ip.proto", ip_proto.to_string()),
            );
            ip_node.add_child(
                TreeNode::new(format!("Header Checksum: 0x{:04x}", checksum))
                    .with_range(offset + 10..offset + 12)
                    .with_field("ip.checksum", format!("0x{:04x}", checksum)),
            );
            ip_node.add_child(
                TreeNode::new(format!("Source Address: {}", src_ip))
                    .with_range(offset + 12..offset + 16)
                    .with_field("ip.src", src_ip.to_string()),
            );
            ip_node.add_child(
                TreeNode::new(format!("Destination Address: {}", dst_ip))
                    .with_range(offset + 16..offset + 20)
                    .with_field("ip.dst", dst_ip.to_string()),
            );
            tree.add_root(ip_node);
        } else if ether_type == 0x86dd && data.len() >= offset + 40 {
            // IPv6
            let ip6_bytes = &data[offset..];
            let payload_len = u16::from_be_bytes([ip6_bytes[4], ip6_bytes[5]]) as usize;
            let next_header = ip6_bytes[6];
            let hop_limit = ip6_bytes[7];

            let mut src_bytes = [0u8; 16];
            src_bytes.copy_from_slice(&ip6_bytes[8..24]);
            let src_ip6 = Ipv6Addr::from(src_bytes);

            let mut dst_bytes = [0u8; 16];
            dst_bytes.copy_from_slice(&ip6_bytes[24..40]);
            let dst_ip6 = Ipv6Addr::from(dst_bytes);

            src_str = src_ip6.to_string();
            dst_str = dst_ip6.to_string();
            ip_proto = next_header;
            transport_offset = offset + 40;

            let mut ip6_node = TreeNode::new(format!(
                "Internet Protocol Version 6, Src: {}, Dst: {}",
                src_ip6, dst_ip6
            ))
            .with_range(offset..offset + 40)
            .with_field("ipv6", "")
            .with_expanded(true);

            ip6_node.add_child(
                TreeNode::new(format!("Payload Length: {}", payload_len))
                    .with_range(offset + 4..offset + 6)
                    .with_field("ipv6.plen", payload_len.to_string()),
            );
            ip6_node.add_child(
                TreeNode::new(format!("Next Header: {}", next_header))
                    .with_range(offset + 6..offset + 7)
                    .with_field("ipv6.nxt", next_header.to_string()),
            );
            ip6_node.add_child(
                TreeNode::new(format!("Hop Limit: {}", hop_limit))
                    .with_range(offset + 7..offset + 8)
                    .with_field("ipv6.hlim", hop_limit.to_string()),
            );
            ip6_node.add_child(
                TreeNode::new(format!("Source Address: {}", src_ip6))
                    .with_range(offset + 8..offset + 24)
                    .with_field("ipv6.src", src_ip6.to_string()),
            );
            ip6_node.add_child(
                TreeNode::new(format!("Destination Address: {}", dst_ip6))
                    .with_range(offset + 24..offset + 40)
                    .with_field("ipv6.dst", dst_ip6.to_string()),
            );
            tree.add_root(ip6_node);
        } else if ether_type == 0x0806 && data.len() >= offset + 28 {
            // ARP
            protocol = String::from("ARP");
            let arp_bytes = &data[offset..];
            let hw_type = u16::from_be_bytes([arp_bytes[0], arp_bytes[1]]);
            let proto_type = u16::from_be_bytes([arp_bytes[2], arp_bytes[3]]);
            let opcode = u16::from_be_bytes([arp_bytes[6], arp_bytes[7]]);
            let sender_mac = format_mac(&arp_bytes[8..14]);
            let sender_ip = Ipv4Addr::new(arp_bytes[14], arp_bytes[15], arp_bytes[16], arp_bytes[17]);
            let target_mac = format_mac(&arp_bytes[18..24]);
            let target_ip = Ipv4Addr::new(arp_bytes[24], arp_bytes[25], arp_bytes[26], arp_bytes[27]);

            let op_desc = match opcode {
                1 => "Request",
                2 => "Reply",
                _ => "Unknown",
            };

            info = if opcode == 1 {
                format!("Who has {}? Tell {}", target_ip, sender_ip)
            } else {
                format!("{} is at {}", sender_ip, sender_mac)
            };

            let mut arp_node = TreeNode::new(format!("Address Resolution Protocol ({})", op_desc))
                .with_range(offset..offset + 28)
                .with_field("arp", "")
                .with_expanded(true);
            arp_node.add_child(
                TreeNode::new(format!("Hardware type: {}", hw_type))
                    .with_range(offset..offset + 2)
                    .with_field("arp.hw.type", hw_type.to_string()),
            );
            arp_node.add_child(
                TreeNode::new(format!("Protocol type: 0x{:04x}", proto_type))
                    .with_range(offset + 2..offset + 4)
                    .with_field("arp.proto.type", format!("0x{:04x}", proto_type)),
            );
            arp_node.add_child(
                TreeNode::new(format!("Opcode: {} ({})", op_desc, opcode))
                    .with_range(offset + 6..offset + 8)
                    .with_field("arp.opcode", opcode.to_string()),
            );
            arp_node.add_child(
                TreeNode::new(format!("Sender MAC: {}", sender_mac))
                    .with_range(offset + 8..offset + 14)
                    .with_field("arp.src.hw_mac", sender_mac),
            );
            arp_node.add_child(
                TreeNode::new(format!("Sender IP: {}", sender_ip))
                    .with_range(offset + 14..offset + 18)
                    .with_field("arp.src.proto_ipv4", sender_ip.to_string()),
            );
            arp_node.add_child(
                TreeNode::new(format!("Target MAC: {}", target_mac))
                    .with_range(offset + 18..offset + 24)
                    .with_field("arp.dst.hw_mac", target_mac),
            );
            arp_node.add_child(
                TreeNode::new(format!("Target IP: {}", target_ip))
                    .with_range(offset + 24..offset + 28)
                    .with_field("arp.dst.proto_ipv4", target_ip.to_string()),
            );
            tree.add_root(arp_node);

            return PacketRecord {
                summary: PacketSummary {
                    num,
                    rel_time_secs,
                    src: sender_ip.to_string(),
                    dst: target_ip.to_string(),
                    protocol,
                    length: total_len,
                    info,
                },
                raw_data: data.to_vec(),
                timestamp_secs: ts_secs,
                timestamp_nanos: ts_nanos,
                tree,
            };
        }

        // 4. Transport Layer Dissection
        let mut app_offset = transport_offset;

        if ip_proto == 6 && data.len() >= transport_offset + 20 {
            // TCP
            protocol = String::from("TCP");
            let tcp = &data[transport_offset..];
            let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
            let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
            let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
            let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
            let data_offset = (tcp[12] >> 4) as usize * 4;
            let flags = tcp[13];
            let window = u16::from_be_bytes([tcp[14], tcp[15]]);
            let checksum = u16::from_be_bytes([tcp[16], tcp[17]]);
            let _urgent = u16::from_be_bytes([tcp[18], tcp[19]]);

            let syn = (flags & 0x02) != 0;
            let ack_flag = (flags & 0x10) != 0;
            let fin = (flags & 0x01) != 0;
            let rst = (flags & 0x04) != 0;
            let psh = (flags & 0x08) != 0;

            let mut flag_strs = Vec::new();
            if syn { flag_strs.push("SYN"); }
            if ack_flag { flag_strs.push("ACK"); }
            if fin { flag_strs.push("FIN"); }
            if rst { flag_strs.push("RST"); }
            if psh { flag_strs.push("PSH"); }
            let flags_summary = if flag_strs.is_empty() {
                String::new()
            } else {
                format!("[{}] ", flag_strs.join(", "))
            };

            app_offset = transport_offset + data_offset;
            let payload_len = if data.len() >= app_offset {
                data.len() - app_offset
            } else {
                0
            };

            info = format!(
                "{} → {} {}Seq={} Ack={} Win={} Len={}",
                src_port, dst_port, flags_summary, seq, ack, window, payload_len
            );

            let mut tcp_node = TreeNode::new(format!(
                "Transmission Control Protocol, Src Port: {}, Dst Port: {}, Seq: {}, Ack: {}",
                src_port, dst_port, seq, ack
            ))
            .with_range(transport_offset..(transport_offset + data_offset))
            .with_field("tcp", "")
            .with_expanded(true);

            tcp_node.add_child(
                TreeNode::new(format!("Source Port: {}", src_port))
                    .with_range(transport_offset..transport_offset + 2)
                    .with_field("tcp.srcport", src_port.to_string()),
            );
            tcp_node.add_child(
                TreeNode::new(format!("Destination Port: {}", dst_port))
                    .with_range(transport_offset + 2..transport_offset + 4)
                    .with_field("tcp.dstport", dst_port.to_string()),
            );
            tcp_node.add_child(
                TreeNode::new(format!("Sequence Number: {} (raw)", seq))
                    .with_range(transport_offset + 4..transport_offset + 8)
                    .with_field("tcp.seq", seq.to_string()),
            );
            tcp_node.add_child(
                TreeNode::new(format!("Acknowledgment Number: {}", ack))
                    .with_range(transport_offset + 8..transport_offset + 12)
                    .with_field("tcp.ack", ack.to_string()),
            );
            tcp_node.add_child(
                TreeNode::new(format!("Header Length: {} bytes ({})", data_offset, data_offset / 4))
                    .with_range(transport_offset + 12..transport_offset + 13)
                    .with_field("tcp.hdr_len", data_offset.to_string()),
            );
            tcp_node.add_child(
                TreeNode::new(format!("Flags: 0x{:03x} ({})", flags, flags_summary.trim()))
                    .with_range(transport_offset + 12..transport_offset + 14)
                    .with_field("tcp.flags", format!("0x{:03x}", flags)),
            );
            tcp_node.add_child(
                TreeNode::new(format!("Window Size: {}", window))
                    .with_range(transport_offset + 14..transport_offset + 16)
                    .with_field("tcp.window_size_value", window.to_string()),
            );
            tcp_node.add_child(
                TreeNode::new(format!("Checksum: 0x{:04x}", checksum))
                    .with_range(transport_offset + 16..transport_offset + 18)
                    .with_field("tcp.checksum", format!("0x{:04x}", checksum)),
            );
            tree.add_root(tcp_node);

            // 5. Application Layer over TCP
            if payload_len > 0 && data.len() >= app_offset {
                let payload = &data[app_offset..];
                if src_port == 23 || dst_port == 23 {
                    // Telnet
                    protocol = String::from("Telnet");
                    let (telnet_node, telnet_info) = dissect_telnet(payload, app_offset);
                    tree.add_root(telnet_node);
                    if !telnet_info.is_empty() {
                        info = format!("{} → {} Telnet: {}", src_port, dst_port, telnet_info);
                    }
                } else if src_port == 80 || dst_port == 80 || src_port == 8080 || dst_port == 8080 {
                    // HTTP
                    if let Some((http_node, http_info)) = dissect_http(payload, app_offset) {
                        protocol = String::from("HTTP");
                        tree.add_root(http_node);
                        info = http_info;
                    } else {
                        tree.add_root(dissect_payload(payload, app_offset));
                    }
                } else if src_port == 443 || dst_port == 443 || src_port == 8443 || dst_port == 8443 {
                    // TLS
                    if let Some((tls_node, tls_info)) = dissect_tls(payload, app_offset) {
                        protocol = String::from("TLS");
                        tree.add_root(tls_node);
                        info = format!("{} → {} {}", src_port, dst_port, tls_info);
                    } else {
                        tree.add_root(dissect_payload(payload, app_offset));
                    }
                } else {
                    tree.add_root(dissect_payload(payload, app_offset));
                }
            }
        } else if ip_proto == 17 && data.len() >= transport_offset + 8 {
            // UDP
            protocol = String::from("UDP");
            let udp = &data[transport_offset..];
            let src_port = u16::from_be_bytes([udp[0], udp[1]]);
            let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
            let len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
            let checksum = u16::from_be_bytes([udp[6], udp[7]]);

            app_offset = transport_offset + 8;
            let payload_len = if data.len() >= app_offset {
                data.len() - app_offset
            } else {
                0
            };

            info = format!("{} → {} Len={}", src_port, dst_port, payload_len);

            let mut udp_node = TreeNode::new(format!(
                "User Datagram Protocol, Src Port: {}, Dst Port: {}",
                src_port, dst_port
            ))
            .with_range(transport_offset..transport_offset + 8)
            .with_field("udp", "")
            .with_expanded(true);

            udp_node.add_child(
                TreeNode::new(format!("Source Port: {}", src_port))
                    .with_range(transport_offset..transport_offset + 2)
                    .with_field("udp.srcport", src_port.to_string()),
            );
            udp_node.add_child(
                TreeNode::new(format!("Destination Port: {}", dst_port))
                    .with_range(transport_offset + 2..transport_offset + 4)
                    .with_field("udp.dstport", dst_port.to_string()),
            );
            udp_node.add_child(
                TreeNode::new(format!("Length: {}", len))
                    .with_range(transport_offset + 4..transport_offset + 6)
                    .with_field("udp.length", len.to_string()),
            );
            udp_node.add_child(
                TreeNode::new(format!("Checksum: 0x{:04x}", checksum))
                    .with_range(transport_offset + 6..transport_offset + 8)
                    .with_field("udp.checksum", format!("0x{:04x}", checksum)),
            );
            tree.add_root(udp_node);

            // 5. Application Layer over UDP
            if payload_len > 0 && data.len() >= app_offset {
                let payload = &data[app_offset..];
                if src_port == 53 || dst_port == 53 {
                    // DNS
                    if let Some((dns_node, dns_info)) = dissect_dns(payload, app_offset) {
                        protocol = String::from("DNS");
                        tree.add_root(dns_node);
                        info = dns_info;
                    } else {
                        tree.add_root(dissect_payload(payload, app_offset));
                    }
                } else if src_port == 67 || dst_port == 67 || src_port == 68 || dst_port == 68 {
                    // DHCP
                    protocol = String::from("DHCP");
                    let (dhcp_node, dhcp_info) = dissect_dhcp(payload, app_offset);
                    tree.add_root(dhcp_node);
                    info = dhcp_info;
                } else {
                    tree.add_root(dissect_payload(payload, app_offset));
                }
            }
        } else if ip_proto == 1 && data.len() >= transport_offset + 8 {
            // ICMP
            protocol = String::from("ICMP");
            let icmp = &data[transport_offset..];
            let icmp_type = icmp[0];
            let code = icmp[1];
            let checksum = u16::from_be_bytes([icmp[2], icmp[3]]);

            let type_desc = match (icmp_type, code) {
                (0, 0) => "Echo (ping) reply",
                (8, 0) => "Echo (ping) request",
                (3, 0) => "Destination network unreachable",
                (3, 1) => "Destination host unreachable",
                (3, 3) => "Destination port unreachable",
                (11, 0) => "Time-to-live exceeded in transit",
                _ => "ICMP message",
            };

            let id_seq = if icmp.len() >= 8 && (icmp_type == 0 || icmp_type == 8) {
                let id = u16::from_be_bytes([icmp[4], icmp[5]]);
                let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
                format!(" id=0x{:04x}, seq={}", id, seq)
            } else {
                String::new()
            };

            info = format!("{}{}", type_desc, id_seq);

            let mut icmp_node = TreeNode::new(format!("Internet Control Message Protocol: {}", type_desc))
                .with_range(transport_offset..data.len())
                .with_field("icmp", "")
                .with_expanded(true);

            icmp_node.add_child(
                TreeNode::new(format!("Type: {} ({})", icmp_type, type_desc))
                    .with_range(transport_offset..transport_offset + 1)
                    .with_field("icmp.type", icmp_type.to_string()),
            );
            icmp_node.add_child(
                TreeNode::new(format!("Code: {}", code))
                    .with_range(transport_offset + 1..transport_offset + 2)
                    .with_field("icmp.code", code.to_string()),
            );
            icmp_node.add_child(
                TreeNode::new(format!("Checksum: 0x{:04x}", checksum))
                    .with_range(transport_offset + 2..transport_offset + 4)
                    .with_field("icmp.checksum", format!("0x{:04x}", checksum)),
            );
            tree.add_root(icmp_node);
        }

        PacketRecord {
            summary: PacketSummary {
                num,
                rel_time_secs,
                src: src_str,
                dst: dst_str,
                protocol,
                length: total_len,
                info,
            },
            raw_data: data.to_vec(),
            timestamp_secs: ts_secs,
            timestamp_nanos: ts_nanos,
            tree,
        }
    }
}

fn format_mac(bytes: &[u8]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

fn dissect_payload(payload: &[u8], offset: usize) -> TreeNode {
    let mut payload_node = TreeNode::new(format!("Data ({} bytes)", payload.len()))
        .with_range(offset..(offset + payload.len()))
        .with_field("data", "")
        .with_expanded(true);

    let printable_preview: String = payload
        .iter()
        .take(40)
        .map(|&b| if (32..=126).contains(&b) { b as char } else { '.' })
        .collect();

    payload_node.add_child(
        TreeNode::new(format!("Data: \"{}\"", printable_preview))
            .with_range(offset..(offset + payload.len()))
            .with_field("data.data", ""),
    );
    payload_node
}

fn dissect_telnet(payload: &[u8], offset: usize) -> (TreeNode, String) {
    let mut node = TreeNode::new(format!("Telnet Protocol ({} bytes)", payload.len()))
        .with_range(offset..(offset + payload.len()))
        .with_field("telnet", "")
        .with_expanded(true);

    let mut actions = Vec::new();
    let mut i = 0;
    while i < payload.len() {
        if payload[i] == 0xff {
            // IAC
            let cmd = if i + 1 < payload.len() { payload[i + 1] } else { 0 };
            let (cmd_str, len) = match cmd {
                251 => ("WILL", 3),
                252 => ("WONT", 3),
                253 => ("DO", 3),
                254 => ("DONT", 3),
                250 => ("Subnegotiation", 3),
                240 => ("SE", 2),
                241 => ("NOP", 2),
                242 => ("Data Mark", 2),
                243 => ("Break", 2),
                244 => ("Interrupt Process", 2),
                _ => ("Command", 2),
            };
            let opt = if len == 3 && i + 2 < payload.len() {
                format!(" 0x{:02x}", payload[i + 2])
            } else {
                String::new()
            };
            let act_desc = format!("IAC {}{}", cmd_str, opt);
            node.add_child(
                TreeNode::new(format!("Command: {}", act_desc))
                    .with_range((offset + i)..((offset + i + len).min(offset + payload.len())))
                    .with_field("telnet.cmd", cmd_str),
            );
            actions.push(act_desc);
            i += len;
        } else {
            // Text chunk
            let start = i;
            while i < payload.len() && payload[i] != 0xff {
                i += 1;
            }
            let text: String = payload[start..i]
                .iter()
                .map(|&b| if (32..=126).contains(&b) { b as char } else { '.' })
                .collect();
            if !text.is_empty() {
                node.add_child(
                    TreeNode::new(format!("Data: \"{}\"", text))
                        .with_range((offset + start)..(offset + i))
                        .with_field("telnet.data", text.clone()),
                );
                actions.push(format!("\"{}\"", text));
            }
        }
    }

    let summary = actions.join(", ");
    (node, summary)
}

fn dissect_http(payload: &[u8], offset: usize) -> Option<(TreeNode, String)> {
    let s = std::str::from_utf8(payload).ok()?;
    let first_line = s.lines().next()?;

    let is_request = first_line.starts_with("GET ")
        || first_line.starts_with("POST ")
        || first_line.starts_with("PUT ")
        || first_line.starts_with("DELETE ")
        || first_line.starts_with("HEAD ")
        || first_line.starts_with("OPTIONS ");
    let is_response = first_line.starts_with("HTTP/1.0 ") || first_line.starts_with("HTTP/1.1 ");

    if !is_request && !is_response {
        return None;
    }

    let title = if is_request {
        format!("Hypertext Transfer Protocol (Request: {})", first_line)
    } else {
        format!("Hypertext Transfer Protocol (Response: {})", first_line)
    };

    let mut node = TreeNode::new(title)
        .with_range(offset..(offset + payload.len()))
        .with_field("http", "")
        .with_expanded(true);

    let mut current_pos = offset;
    for line in s.lines() {
        let line_len = line.len() + 1; // approx + newline
        node.add_child(
            TreeNode::new(line)
                .with_range(current_pos..(current_pos + line.len()))
                .with_field("http.line", line),
        );
        current_pos += line_len;
    }

    Some((node, first_line.to_string()))
}

fn dissect_dns(payload: &[u8], offset: usize) -> Option<(TreeNode, String)> {
    if payload.len() < 12 {
        return None;
    }
    let tx_id = u16::from_be_bytes([payload[0], payload[1]]);
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let q_count = u16::from_be_bytes([payload[4], payload[5]]);
    let ans_count = u16::from_be_bytes([payload[6], payload[7]]);

    let is_response = (flags & 0x8000) != 0;
    let rcode = flags & 0x000f;

    let op_str = if is_response { "response" } else { "query" };

    // Parse question name if present
    let mut qname = String::new();
    let mut pos = 12;
    while pos < payload.len() && payload[pos] != 0 {
        let label_len = payload[pos] as usize;
        pos += 1;
        if pos + label_len <= payload.len() {
            if !qname.is_empty() {
                qname.push('.');
            }
            if let Ok(label) = std::str::from_utf8(&payload[pos..pos + label_len]) {
                qname.push_str(label);
            }
            pos += label_len;
        } else {
            break;
        }
    }

    let info = if is_response {
        format!("Standard query response 0x{:04x} (Answers: {}) {}", tx_id, ans_count, qname)
    } else {
        format!("Standard query 0x{:04x} A {}", tx_id, qname)
    };

    let mut node = TreeNode::new(format!("Domain Name System ({})", op_str))
        .with_range(offset..(offset + payload.len()))
        .with_field("dns", "")
        .with_expanded(true);

    node.add_child(
        TreeNode::new(format!("Transaction ID: 0x{:04x}", tx_id))
            .with_range(offset..offset + 2)
            .with_field("dns.id", format!("0x{:04x}", tx_id)),
    );
    node.add_child(
        TreeNode::new(format!("Flags: 0x{:04x} (Response: {}, Rcode: {})", flags, is_response, rcode))
            .with_range(offset + 2..offset + 4)
            .with_field("dns.flags", format!("0x{:04x}", flags)),
    );
    node.add_child(
        TreeNode::new(format!("Questions: {}", q_count))
            .with_range(offset + 4..offset + 6)
            .with_field("dns.count.queries", q_count.to_string()),
    );
    node.add_child(
        TreeNode::new(format!("Answer RRs: {}", ans_count))
            .with_range(offset + 6..offset + 8)
            .with_field("dns.count.answers", ans_count.to_string()),
    );
    if !qname.is_empty() {
        node.add_child(
            TreeNode::new(format!("Query Name: {}", qname))
                .with_range(offset + 12..(offset + pos.min(payload.len())))
                .with_field("dns.qry.name", qname),
        );
    }

    Some((node, info))
}

fn dissect_tls(payload: &[u8], offset: usize) -> Option<(TreeNode, String)> {
    if payload.len() < 5 {
        return None;
    }
    let content_type = payload[0];
    let version_major = payload[1];
    let version_minor = payload[2];
    let _length = u16::from_be_bytes([payload[3], payload[4]]) as usize;

    let type_name = match content_type {
        20 => "Change Cipher Spec",
        21 => "Alert",
        22 => "Handshake",
        23 => "Application Data",
        24 => "Heartbeat",
        _ => return None,
    };

    let version_str = match (version_major, version_minor) {
        (3, 1) => "TLS 1.0",
        (3, 2) => "TLS 1.1",
        (3, 3) => "TLS 1.2",
        (3, 4) => "TLS 1.3",
        _ => "TLS",
    };

    let mut info = format!("{} Record Layer: {}", version_str, type_name);
    let mut node = TreeNode::new(format!("Transport Layer Security ({}, {})", version_str, type_name))
        .with_range(offset..(offset + payload.len()))
        .with_field("tls", "")
        .with_expanded(true);

    if content_type == 22 && payload.len() >= 6 {
        let handshake_type = payload[5];
        let hs_desc = match handshake_type {
            1 => "Client Hello",
            2 => "Server Hello",
            11 => "Certificate",
            12 => "Server Key Exchange",
            14 => "Server Hello Done",
            16 => "Client Key Exchange",
            _ => "Handshake Message",
        };
        info = format!("{} {}", version_str, hs_desc);
        node.add_child(
            TreeNode::new(format!("Handshake Protocol: {}", hs_desc))
                .with_range(offset + 5..offset + payload.len())
                .with_field("tls.handshake.type", handshake_type.to_string()),
        );
    }

    Some((node, info))
}

fn dissect_dhcp(payload: &[u8], offset: usize) -> (TreeNode, String) {
    let mut node = TreeNode::new(format!("Dynamic Host Configuration Protocol ({} bytes)", payload.len()))
        .with_range(offset..(offset + payload.len()))
        .with_field("dhcp", "")
        .with_expanded(true);

    let op = if !payload.is_empty() { payload[0] } else { 0 };
    let op_desc = if op == 1 { "Boot Request" } else { "Boot Reply" };

    let mut info = format!("DHCP {}", op_desc);

    // Look for magic cookie 0x63, 0x82, 0x53, 0x63 at offset 236
    if payload.len() > 240 && payload[236..240] == [99, 130, 83, 99] {
        let mut opt_idx = 240;
        while opt_idx < payload.len() {
            let opt_code = payload[opt_idx];
            if opt_code == 255 {
                break;
            } // End
            if opt_code == 0 {
                opt_idx += 1;
                continue;
            } // Pad
            if opt_idx + 1 >= payload.len() {
                break;
            }
            let opt_len = payload[opt_idx + 1] as usize;
            if opt_idx + 2 + opt_len > payload.len() {
                break;
            }
            if opt_code == 53 && opt_len == 1 {
                // DHCP Message Type
                let msg_type = payload[opt_idx + 2];
                let msg_desc = match msg_type {
                    1 => "Discover",
                    2 => "Offer",
                    3 => "Request",
                    4 => "Decline",
                    5 => "ACK",
                    6 => "NAK",
                    7 => "Release",
                    8 => "Inform",
                    _ => "Unknown",
                };
                info = format!("DHCP {}", msg_desc);
                node.add_child(
                    TreeNode::new(format!("Option: (53) DHCP Message Type = DHCP {}", msg_desc))
                        .with_range((offset + opt_idx)..(offset + opt_idx + 2 + opt_len))
                        .with_field("dhcp.type", msg_desc),
                );
            }
            opt_idx += 2 + opt_len;
        }
    }

    (node, info)
}
