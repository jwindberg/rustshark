use super::PacketRecord;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvType {
    Ethernet,
    IPv4,
    IPv6,
    TCP,
    UDP,
}

#[derive(Debug, Clone)]
pub struct ConvRow {
    pub endpoint_a: String,
    pub endpoint_b: String,
    pub pkts_a_to_b: usize,
    pub bytes_a_to_b: usize,
    pub pkts_b_to_a: usize,
    pub bytes_b_to_a: usize,
    pub total_pkts: usize,
    pub total_bytes: usize,
}

#[derive(Debug, Clone, Default)]
pub struct Conversations {
    pub eth_convs: Vec<ConvRow>,
    pub ip4_convs: Vec<ConvRow>,
    pub ip6_convs: Vec<ConvRow>,
    pub tcp_convs: Vec<ConvRow>,
    pub udp_convs: Vec<ConvRow>,
}

impl Conversations {
    pub fn build(packets: &[PacketRecord]) -> Self {
        let mut eth_map: HashMap<(String, String), (usize, usize, usize, usize)> = HashMap::new();
        let mut ip4_map: HashMap<(String, String), (usize, usize, usize, usize)> = HashMap::new();
        let mut ip6_map: HashMap<(String, String), (usize, usize, usize, usize)> = HashMap::new();
        let mut tcp_map: HashMap<(String, String), (usize, usize, usize, usize)> = HashMap::new();
        let mut udp_map: HashMap<(String, String), (usize, usize, usize, usize)> = HashMap::new();

        for pkt in packets {
            let len = pkt.summary.length;

            // IP level
            let src = &pkt.summary.src;
            let dst = &pkt.summary.dst;

            if src.contains('.') && dst.contains('.') {
                add_to_map(&mut ip4_map, src, dst, len);
            } else if src.contains(':') && dst.contains(':') && !src.contains('-') && src.len() > 17 {
                add_to_map(&mut ip6_map, src, dst, len);
            }

            // MAC level
            let mut mac_src = None;
            let mut mac_dst = None;
            for n in &pkt.tree.root_nodes {
                if n.field_name == "eth" {
                    for c in &n.children {
                        if c.field_name == "eth.src" {
                            mac_src = Some(c.field_val.clone());
                        }
                        if c.field_name == "eth.dst" {
                            mac_dst = Some(c.field_val.clone());
                        }
                    }
                }
            }
            if let (Some(ms), Some(md)) = (mac_src, mac_dst) {
                add_to_map(&mut eth_map, &ms, &md, len);
            }

            // TCP / UDP level
            let mut src_port = None;
            let mut dst_port = None;
            let is_tcp = pkt.summary.protocol.to_uppercase() == "TCP"
                || pkt.summary.protocol.to_uppercase() == "HTTP"
                || pkt.summary.protocol.to_uppercase() == "TELNET"
                || pkt.summary.protocol.to_uppercase() == "TLS";
            let is_udp = pkt.summary.protocol.to_uppercase() == "UDP" || pkt.summary.protocol.to_uppercase() == "DNS";

            for n in &pkt.tree.root_nodes {
                for c in &n.children {
                    if c.field_name.ends_with("srcport") {
                        src_port = Some(c.field_val.clone());
                    }
                    if c.field_name.ends_with("dstport") {
                        dst_port = Some(c.field_val.clone());
                    }
                }
            }

            if let (Some(sp), Some(dp)) = (src_port, dst_port) {
                let ep_a = format!("{}:{}", src, sp);
                let ep_b = format!("{}:{}", dst, dp);
                if is_tcp {
                    add_to_map(&mut tcp_map, &ep_a, &ep_b, len);
                } else if is_udp {
                    add_to_map(&mut udp_map, &ep_a, &ep_b, len);
                }
            }
        }

        Self {
            eth_convs: map_to_sorted_vec(eth_map),
            ip4_convs: map_to_sorted_vec(ip4_map),
            ip6_convs: map_to_sorted_vec(ip6_map),
            tcp_convs: map_to_sorted_vec(tcp_map),
            udp_convs: map_to_sorted_vec(udp_map),
        }
    }
}

fn add_to_map(
    map: &mut HashMap<(String, String), (usize, usize, usize, usize)>,
    src: &str,
    dst: &str,
    len: usize,
) {
    if src <= dst {
        let entry = map.entry((src.to_string(), dst.to_string())).or_default();
        entry.0 += 1;
        entry.1 += len;
    } else {
        let entry = map.entry((dst.to_string(), src.to_string())).or_default();
        entry.2 += 1;
        entry.3 += len;
    }
}

fn map_to_sorted_vec(map: HashMap<(String, String), (usize, usize, usize, usize)>) -> Vec<ConvRow> {
    let mut vec: Vec<ConvRow> = map
        .into_iter()
        .map(|((a, b), (p_ab, b_ab, p_ba, b_ba))| ConvRow {
            endpoint_a: a,
            endpoint_b: b,
            pkts_a_to_b: p_ab,
            bytes_a_to_b: b_ab,
            pkts_b_to_a: p_ba,
            bytes_b_to_a: b_ba,
            total_pkts: p_ab + p_ba,
            total_bytes: b_ab + b_ba,
        })
        .collect();

    vec.sort_by(|x, y| y.total_bytes.cmp(&x.total_bytes));
    vec
}

impl ConvRow {
    pub fn to_filter(&self, conv_type: ConvType) -> String {
        match conv_type {
            ConvType::Ethernet => {
                format!("eth.addr == {} and eth.addr == {}", self.endpoint_a, self.endpoint_b)
            }
            ConvType::IPv4 | ConvType::IPv6 => {
                format!("ip.addr == {} and ip.addr == {}", self.endpoint_a, self.endpoint_b)
            }
            ConvType::TCP => {
                let parts_a: Vec<&str> = self.endpoint_a.rsplitn(2, ':').collect();
                let parts_b: Vec<&str> = self.endpoint_b.rsplitn(2, ':').collect();
                if parts_a.len() == 2 && parts_b.len() == 2 {
                    format!(
                        "(ip.addr == {} and tcp.port == {}) and (ip.addr == {} and tcp.port == {})",
                        parts_a[1], parts_a[0], parts_b[1], parts_b[0]
                    )
                } else {
                    format!("ip.addr == {} and ip.addr == {}", self.endpoint_a, self.endpoint_b)
                }
            }
            ConvType::UDP => {
                let parts_a: Vec<&str> = self.endpoint_a.rsplitn(2, ':').collect();
                let parts_b: Vec<&str> = self.endpoint_b.rsplitn(2, ':').collect();
                if parts_a.len() == 2 && parts_b.len() == 2 {
                    format!(
                        "(ip.addr == {} and udp.port == {}) and (ip.addr == {} and udp.port == {})",
                        parts_a[1], parts_a[0], parts_b[1], parts_b[0]
                    )
                } else {
                    format!("ip.addr == {} and ip.addr == {}", self.endpoint_a, self.endpoint_b)
                }
            }
        }
    }
}
