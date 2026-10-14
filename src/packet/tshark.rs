#![allow(dead_code)]

use super::{DissectionTree, PacketSummary, TreeNode};
use anyhow::{Context, Result};
use std::process::Command;

#[allow(dead_code)]
pub struct TsharkBridge {
    pub bin_path: String,
}

impl Default for TsharkBridge {
    fn default() -> Self {
        Self::new("tshark")
    }
}

impl TsharkBridge {
    pub fn new(bin_path: impl Into<String>) -> Self {
        Self {
            bin_path: bin_path.into(),
        }
    }

    pub fn is_available(&self) -> bool {
        Command::new(&self.bin_path)
            .arg("-v")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }

    pub fn read_psml(&self, pcap_path: &str, display_filter: Option<&str>) -> Result<Vec<PacketSummary>> {
        let mut cmd = Command::new(&self.bin_path);
        cmd.args(["-r", pcap_path, "-T", "psml"]);
        if let Some(df) = display_filter {
            if !df.trim().is_empty() {
                cmd.args(["-Y", df]);
            }
        }

        let output = cmd.output().context("Failed to execute tshark")?;
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("tshark error: {}", err);
        }

        parse_psml_xml(&output.stdout)
    }

    pub fn read_pdml_packet(&self, pcap_path: &str, packet_num: usize) -> Result<DissectionTree> {
        let filter = format!("frame.number == {}", packet_num);
        let mut cmd = Command::new(&self.bin_path);
        cmd.args(["-r", pcap_path, "-T", "pdml", "-Y", &filter]);

        let output = cmd.output().context("Failed to execute tshark for PDML")?;
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("tshark pdml error: {}", err);
        }

        parse_pdml_xml(&output.stdout)
    }
}

fn parse_psml_xml(xml_bytes: &[u8]) -> Result<Vec<PacketSummary>> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    let mut reader = Reader::from_reader(xml_bytes);
    reader.config_mut().trim_text(true);

    let mut packets = Vec::new();
    let mut in_packet = false;
    let mut in_section = false;
    let mut current_sections: Vec<String> = Vec::new();
    let mut current_text = String::new();

    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                "packet" => {
                    in_packet = true;
                    current_sections.clear();
                }
                "section" => {
                    in_section = true;
                    current_text.clear();
                }
                _ => {}
            },
            Ok(Event::Text(e)) => {
                if in_section {
                    current_text.push_str(e.as_ref());
                }
            }
            Ok(Event::End(e)) => match e.name().as_ref() {
                "section" => {
                    in_section = false;
                    current_sections.push(current_text.clone());
                    current_text.clear();
                }
                "packet" => {
                    in_packet = false;
                    if !current_sections.is_empty() {
                        let num = current_sections.first().and_then(|s| s.parse().ok()).unwrap_or(packets.len() + 1);
                        let rel_time = current_sections.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.0);
                        let src = current_sections.get(2).cloned().unwrap_or_default();
                        let dst = current_sections.get(3).cloned().unwrap_or_default();
                        let protocol = current_sections.get(4).cloned().unwrap_or_else(|| "Unknown".to_string());
                        let length = current_sections.get(5).and_then(|s| s.parse().ok()).unwrap_or(0);
                        let info = current_sections.get(6).cloned().unwrap_or_default();

                        packets.push(PacketSummary {
                            num,
                            rel_time_secs: rel_time,
                            src,
                            dst,
                            protocol,
                            length,
                            info,
                        });
                    }
                }
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(e) => anyhow::bail!("XML parse error: {}", e),
            _ => {}
        }
        buf.clear();
    }

    let _ = in_packet;
    Ok(packets)
}

fn parse_pdml_xml(xml_bytes: &[u8]) -> Result<DissectionTree> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    let mut reader = Reader::from_reader(xml_bytes);
    reader.config_mut().trim_text(true);

    let mut tree = DissectionTree::new();
    let mut node_stack: Vec<TreeNode> = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let elem_name = e.name();
                let tag = elem_name.as_ref();
                if tag == "proto" || tag == "field" {
                    let mut title = String::new();
                    let mut field_name = String::new();
                    let mut field_val = String::new();
                    let mut pos = 0usize;
                    let mut size = 0usize;

                    for attr in e.attributes().flatten() {
                        let key_str = attr.key.as_ref();
                        let val_str = attr.value.to_string();
                        match key_str {
                            "showname" => title = val_str,
                            "name" => field_name = val_str,
                            "show" | "value" => {
                                if field_val.is_empty() {
                                    field_val = val_str;
                                }
                            }
                            "pos" => pos = val_str.parse().unwrap_or(0),
                            "size" => size = val_str.parse().unwrap_or(0),
                            _ => {}
                        }
                    }

                    if title.is_empty() {
                        title = if !field_val.is_empty() {
                            format!("{}: {}", field_name, field_val)
                        } else {
                            field_name.clone()
                        };
                    }

                    let node = TreeNode::new(title)
                        .with_range(pos..(pos + size))
                        .with_field(field_name, field_val)
                        .with_expanded(node_stack.is_empty());

                    node_stack.push(node);
                }
            }
            Ok(Event::Empty(e)) => {
                let elem_name = e.name();
                let tag = elem_name.as_ref();
                if tag == "field" {
                    let mut title = String::new();
                    let mut field_name = String::new();
                    let mut field_val = String::new();
                    let mut pos = 0usize;
                    let mut size = 0usize;

                    for attr in e.attributes().flatten() {
                        let key_str = attr.key.as_ref();
                        let val_str = attr.value.to_string();
                        match key_str {
                            "showname" => title = val_str,
                            "name" => field_name = val_str,
                            "show" | "value" => {
                                if field_val.is_empty() {
                                    field_val = val_str;
                                }
                            }
                            "pos" => pos = val_str.parse().unwrap_or(0),
                            "size" => size = val_str.parse().unwrap_or(0),
                            _ => {}
                        }
                    }

                    if title.is_empty() {
                        title = if !field_val.is_empty() {
                            format!("{}: {}", field_name, field_val)
                        } else {
                            field_name.clone()
                        };
                    }

                    let node = TreeNode::new(title)
                        .with_range(pos..(pos + size))
                        .with_field(field_name, field_val);

                    if let Some(parent) = node_stack.last_mut() {
                        parent.add_child(node);
                    } else {
                        tree.add_root(node);
                    }
                }
            }
            Ok(Event::End(e)) => {
                let elem_name = e.name();
                let tag = elem_name.as_ref();
                if (tag == "proto" || tag == "field") && !node_stack.is_empty() {
                    let node = node_stack.pop().unwrap();
                    if let Some(parent) = node_stack.last_mut() {
                        parent.add_child(node);
                    } else {
                        tree.add_root(node);
                    }
                }
            }
            Ok(Event::Eof) => break,
            _ => {}
        }
        buf.clear();
    }

    Ok(tree)
}
