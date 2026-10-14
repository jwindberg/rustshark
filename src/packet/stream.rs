#![allow(dead_code)]

use super::PacketRecord;

#[derive(Debug, Clone)]
pub struct StreamChunk {
    pub is_client: bool,
    pub packet_num: usize,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct StreamReassembly {
    pub client_endpoint: String,
    pub server_endpoint: String,
    pub protocol: String,
    pub chunks: Vec<StreamChunk>,
    pub total_client_bytes: usize,
    pub total_server_bytes: usize,
}

impl StreamReassembly {
    /// Reassemble the stream containing the target packet from the packet collection
    pub fn reassemble_for_packet(target: &PacketRecord, all_packets: &[PacketRecord]) -> Option<Self> {
        let proto = target.summary.protocol.to_uppercase();
        if proto != "TCP" && proto != "UDP" && proto != "TELNET" && proto != "HTTP" && proto != "TLS" {
            return None;
        }

        // Extract endpoint tuple from target packet
        let (ep1, ep2) = extract_endpoints(target)?;
        let client_ep = ep1;
        let server_ep = ep2;

        let mut chunks = Vec::new();
        let mut total_client_bytes = 0;
        let mut total_server_bytes = 0;

        for pkt in all_packets {
            if let Some((src, dst)) = extract_endpoints(pkt) {
                let is_forward = src == client_ep && dst == server_ep;
                let is_reverse = src == server_ep && dst == client_ep;

                if is_forward || is_reverse {
                    if let Some(payload) = extract_transport_payload(pkt) {
                        if !payload.is_empty() {
                            if is_forward {
                                total_client_bytes += payload.len();
                            } else {
                                total_server_bytes += payload.len();
                            }
                            chunks.push(StreamChunk {
                                is_client: is_forward,
                                packet_num: pkt.summary.num,
                                data: payload.to_vec(),
                            });
                        }
                    }
                }
            }
        }

        if chunks.is_empty() {
            return None;
        }

        Some(StreamReassembly {
            client_endpoint: client_ep,
            server_endpoint: server_ep,
            protocol: proto,
            chunks,
            total_client_bytes,
            total_server_bytes,
        })
    }
}

fn extract_endpoints(pkt: &PacketRecord) -> Option<(String, String)> {
    let src_ip = &pkt.summary.src;
    let dst_ip = &pkt.summary.dst;

    // Search tree for srcport and dstport
    let mut src_port = None;
    let mut dst_port = None;

    find_ports(&pkt.tree.root_nodes, &mut src_port, &mut dst_port);

    if let (Some(sp), Some(dp)) = (src_port, dst_port) {
        Some((format!("{}:{}", src_ip, sp), format!("{}:{}", dst_ip, dp)))
    } else {
        None
    }
}

fn find_ports(nodes: &[super::TreeNode], src: &mut Option<String>, dst: &mut Option<String>) {
    for n in nodes {
        if n.field_name == "tcp.srcport" || n.field_name == "udp.srcport" {
            *src = Some(n.field_val.clone());
        }
        if n.field_name == "tcp.dstport" || n.field_name == "udp.dstport" {
            *dst = Some(n.field_val.clone());
        }
        find_ports(&n.children, src, dst);
    }
}

fn extract_transport_payload(pkt: &PacketRecord) -> Option<&[u8]> {
    // Find node with field_name == "data" or "telnet" or "http" or "tls"
    for node in &pkt.tree.root_nodes {
        if node.field_name == "data" || node.field_name == "telnet" || node.field_name == "http" || node.field_name == "tls" {
            if let Some(range) = &node.byte_range {
                if range.end <= pkt.raw_data.len() && range.start < range.end {
                    return Some(&pkt.raw_data[range.clone()]);
                }
            }
        }
    }
    None
}
