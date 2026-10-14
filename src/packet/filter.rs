use super::PacketRecord;

#[derive(Debug, Clone)]
pub enum FilterExpr {
    All,
    Protocol(String),
    IpAddr(String),
    IpSrc(String),
    IpDst(String),
    Port(u16),
    SrcPort(u16),
    DstPort(u16),
    LengthGt(usize),
    LengthLt(usize),
    LengthEq(usize),
    Contains(String),
    FieldEquals(String, String),
    And(Box<FilterExpr>, Box<FilterExpr>),
    Or(Box<FilterExpr>, Box<FilterExpr>),
    Not(Box<FilterExpr>),
}

impl FilterExpr {
    pub fn parse(input: &str) -> Result<FilterExpr, String> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(FilterExpr::All);
        }

        // Strip matched outer parentheses
        if trimmed.starts_with('(') && trimmed.ends_with(')') {
            let mut depth = 0;
            let mut matched_outer = true;
            for (i, c) in trimmed.chars().enumerate() {
                if c == '(' {
                    depth += 1;
                } else if c == ')' {
                    depth -= 1;
                    if depth == 0 && i < trimmed.len() - 1 {
                        matched_outer = false;
                        break;
                    }
                }
            }
            if matched_outer {
                return FilterExpr::parse(&trimmed[1..trimmed.len() - 1]);
            }
        }

        // Check for 'or' or '||'
        if let Some((left, right)) = split_binary(trimmed, &[" || ", " or "]) {
            let l = FilterExpr::parse(left)?;
            let r = FilterExpr::parse(right)?;
            return Ok(FilterExpr::Or(Box::new(l), Box::new(r)));
        }

        // Check for 'and' or '&&'
        if let Some((left, right)) = split_binary(trimmed, &[" && ", " and "]) {
            let l = FilterExpr::parse(left)?;
            let r = FilterExpr::parse(right)?;
            return Ok(FilterExpr::And(Box::new(l), Box::new(r)));
        }

        // Check for 'not' or '!'
        if trimmed.starts_with('!') || trimmed.to_lowercase().starts_with("not ") {
            let rest = if trimmed.starts_with('!') {
                &trimmed[1..]
            } else {
                &trimmed[4..]
            };
            let sub = FilterExpr::parse(rest)?;
            return Ok(FilterExpr::Not(Box::new(sub)));
        }

        // Comparison operations: ==, !=, >=, <=, >, <, contains
        if let Some((field, val)) = split_op(trimmed, "==") {
            return parse_comparison(field, val, Op::Eq);
        }
        if let Some((field, val)) = split_op(trimmed, "!=") {
            let sub = parse_comparison(field, val, Op::Eq)?;
            return Ok(FilterExpr::Not(Box::new(sub)));
        }
        if let Some((field, val)) = split_op(trimmed, ">") {
            return parse_comparison(field, val, Op::Gt);
        }
        if let Some((field, val)) = split_op(trimmed, "<") {
            return parse_comparison(field, val, Op::Lt);
        }
        if let Some((_field, val)) = split_op(trimmed, " contains ") {
            let cleaned_val = val.trim_matches('"').trim_matches('\'');
            return Ok(FilterExpr::Contains(cleaned_val.to_string()));
        }

        // Single keyword (protocol or text search)
        let kw = trimmed.to_lowercase();
        match kw.as_str() {
            "tcp" | "udp" | "ip" | "ipv6" | "dns" | "http" | "icmp" | "arp" | "tls" | "telnet" | "dhcp" => {
                Ok(FilterExpr::Protocol(kw))
            }
            _ => {
                // Check if it's an IP address or port number or fallback substring search
                if let Ok(port) = trimmed.parse::<u16>() {
                    Ok(FilterExpr::Port(port))
                } else {
                    Ok(FilterExpr::Contains(trimmed.to_string()))
                }
            }
        }
    }

    pub fn matches(&self, pkt: &PacketRecord) -> bool {
        match self {
            FilterExpr::All => true,
            FilterExpr::Protocol(proto) => {
                let p = proto.to_lowercase();
                pkt.summary.protocol.to_lowercase() == p
                    || (p == "ip" && (pkt.summary.src.contains('.') || pkt.summary.dst.contains('.')))
                    || (p == "ipv6" && (pkt.summary.src.contains(':') || pkt.summary.dst.contains(':')))
                    || pkt.tree.root_nodes.iter().any(|n| n.field_name.to_lowercase().starts_with(&p))
            }
            FilterExpr::IpAddr(addr) => pkt.summary.src == *addr || pkt.summary.dst == *addr,
            FilterExpr::IpSrc(addr) => pkt.summary.src == *addr,
            FilterExpr::IpDst(addr) => pkt.summary.dst == *addr,
            FilterExpr::Port(port) => {
                let p_str = port.to_string();
                has_port(&pkt.summary.info, &p_str)
                    || has_tree_field(&pkt.tree.root_nodes, "srcport", &p_str)
                    || has_tree_field(&pkt.tree.root_nodes, "dstport", &p_str)
            }
            FilterExpr::SrcPort(port) => {
                let p_str = port.to_string();
                has_tree_field(&pkt.tree.root_nodes, "srcport", &p_str)
            }
            FilterExpr::DstPort(port) => {
                let p_str = port.to_string();
                has_tree_field(&pkt.tree.root_nodes, "dstport", &p_str)
            }
            FilterExpr::LengthGt(len) => pkt.summary.length > *len,
            FilterExpr::LengthLt(len) => pkt.summary.length < *len,
            FilterExpr::LengthEq(len) => pkt.summary.length == *len,
            FilterExpr::Contains(needle) => {
                let needle_lower = needle.to_lowercase();
                pkt.summary.src.to_lowercase().contains(&needle_lower)
                    || pkt.summary.dst.to_lowercase().contains(&needle_lower)
                    || pkt.summary.protocol.to_lowercase().contains(&needle_lower)
                    || pkt.summary.info.to_lowercase().contains(&needle_lower)
                    || tree_contains(&pkt.tree.root_nodes, &needle_lower)
            }
            FilterExpr::FieldEquals(field, val) => {
                has_tree_field(&pkt.tree.root_nodes, field, val)
            }
            FilterExpr::And(left, right) => left.matches(pkt) && right.matches(pkt),
            FilterExpr::Or(left, right) => left.matches(pkt) || right.matches(pkt),
            FilterExpr::Not(sub) => !sub.matches(pkt),
        }
    }
}

enum Op {
    Eq,
    Gt,
    Lt,
}

fn split_binary<'a>(input: &'a str, delimiters: &[&str]) -> Option<(&'a str, &'a str)> {
    for &d in delimiters {
        let mut depth: usize = 0;
        let bytes = input.as_bytes();
        let d_bytes = d.as_bytes();
        let mut i = 0;
        while i + d_bytes.len() <= bytes.len() {
            if bytes[i] == b'(' {
                depth += 1;
            } else if bytes[i] == b')' {
                depth = depth.saturating_sub(1);
            } else if depth == 0 && &bytes[i..i + d_bytes.len()] == d_bytes {
                let left = &input[..i];
                let right = &input[i + d_bytes.len()..];
                return Some((left, right));
            }
            i += 1;
        }
    }
    None
}

fn split_op<'a>(input: &'a str, op: &str) -> Option<(&'a str, &'a str)> {
    if let Some(pos) = input.find(op) {
        let left = input[..pos].trim();
        let right = input[pos + op.len()..].trim();
        Some((left, right))
    } else {
        None
    }
}

fn parse_comparison(field: &str, val: &str, op: Op) -> Result<FilterExpr, String> {
    let f = field.to_lowercase();
    let cleaned_val = val.trim_matches('"').trim_matches('\'').trim();

    match op {
        Op::Eq => {
            if f == "ip.addr" || f == "ip" || f == "addr" {
                Ok(FilterExpr::IpAddr(cleaned_val.to_string()))
            } else if f == "ip.src" || f == "src" {
                Ok(FilterExpr::IpSrc(cleaned_val.to_string()))
            } else if f == "ip.dst" || f == "dst" {
                Ok(FilterExpr::IpDst(cleaned_val.to_string()))
            } else if f == "tcp.port" || f == "udp.port" || f == "port" {
                let p = cleaned_val.parse::<u16>().map_err(|e| e.to_string())?;
                Ok(FilterExpr::Port(p))
            } else if f == "tcp.srcport" || f == "udp.srcport" || f == "srcport" {
                let p = cleaned_val.parse::<u16>().map_err(|e| e.to_string())?;
                Ok(FilterExpr::SrcPort(p))
            } else if f == "tcp.dstport" || f == "udp.dstport" || f == "dstport" {
                let p = cleaned_val.parse::<u16>().map_err(|e| e.to_string())?;
                Ok(FilterExpr::DstPort(p))
            } else if f == "frame.len" || f == "len" || f == "length" {
                let len = cleaned_val.parse::<usize>().map_err(|e| e.to_string())?;
                Ok(FilterExpr::LengthEq(len))
            } else {
                Ok(FilterExpr::FieldEquals(f, cleaned_val.to_string()))
            }
        }
        Op::Gt => {
            if f == "frame.len" || f == "len" || f == "length" {
                let len = cleaned_val.parse::<usize>().map_err(|e| e.to_string())?;
                Ok(FilterExpr::LengthGt(len))
            } else {
                Err(format!("Operator > not supported for field {}", field))
            }
        }
        Op::Lt => {
            if f == "frame.len" || f == "len" || f == "length" {
                let len = cleaned_val.parse::<usize>().map_err(|e| e.to_string())?;
                Ok(FilterExpr::LengthLt(len))
            } else {
                Err(format!("Operator < not supported for field {}", field))
            }
        }
    }
}

fn has_port(info: &str, port_str: &str) -> bool {
    info.split(|c: char| !c.is_numeric()).any(|chunk| chunk == port_str)
}

fn has_tree_field(nodes: &[super::TreeNode], field_sub: &str, val: &str) -> bool {
    for n in nodes {
        if n.field_name.to_lowercase().contains(field_sub) && n.field_val == val {
            return true;
        }
        if has_tree_field(&n.children, field_sub, val) {
            return true;
        }
    }
    false
}

fn tree_contains(nodes: &[super::TreeNode], needle_lower: &str) -> bool {
    for n in nodes {
        if n.title.to_lowercase().contains(needle_lower)
            || n.field_name.to_lowercase().contains(needle_lower)
            || n.field_val.to_lowercase().contains(needle_lower)
        {
            return true;
        }
        if tree_contains(&n.children, needle_lower) {
            return true;
        }
    }
    false
}
