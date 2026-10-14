use super::dissector::PacketDissector;
use super::PacketRecord;
use anyhow::{Context, Result};
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::PcapNgReader;
use std::fs::File;
use std::io::{BufReader, Read};

pub struct PacketLoader;

impl PacketLoader {
    pub fn load_from_file(path: &str) -> Result<Vec<PacketRecord>> {
        if path == "-" {
            return Self::load_from_reader(Box::new(std::io::stdin()));
        }
        let file = File::open(path).with_context(|| format!("Failed to open pcap file: {}", path))?;
        Self::load_from_reader(Box::new(file))
    }

    pub fn load_from_reader<R: Read + 'static>(mut reader: Box<R>) -> Result<Vec<PacketRecord>> {
        // Read header bytes to detect PCAP vs PCAPNG
        let mut magic = [0u8; 4];
        let bytes_read = reader.read(&mut magic)?;
        if bytes_read < 4 {
            anyhow::bail!("File too short to be a valid pcap");
        }

        let chained = std::io::Cursor::new(magic).chain(reader);
        let buf_reader = BufReader::new(chained);

        // PCAP magic: 0xa1b2c3d4, 0xd4c3b2a1 (microsec) or 0xa1b23c4d (nanosec)
        // PCAPNG magic: 0x0a0d0d0a
        if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
            Self::load_pcapng(buf_reader)
        } else {
            Self::load_pcap(buf_reader)
        }
    }

    pub fn load_streaming<R: Read + Send + 'static>(
        reader: R,
        sender: std::sync::mpsc::Sender<PacketRecord>,
    ) -> Result<()> {
        let mut pcap_reader = PcapReader::new(reader).context("Failed to initialize PCAP reader")?;
        let link_type = u32::from(pcap_reader.header().datalink);
        let mut first_ts: Option<f64> = None;
        let mut pkt_num = 1;

        while let Some(pkt_res) = pcap_reader.next_packet() {
            if let Ok(pkt) = pkt_res {
                let ts_secs = pkt.timestamp.as_secs();
                let ts_nanos = pkt.timestamp.subsec_nanos();
                let current_ts = ts_secs as f64 + (ts_nanos as f64 / 1_000_000_000.0);

                let rel_time = match first_ts {
                    None => {
                        first_ts = Some(current_ts);
                        0.0
                    }
                    Some(f) => current_ts - f,
                };

                let record = PacketDissector::dissect(
                    pkt_num,
                    rel_time,
                    ts_secs,
                    ts_nanos,
                    &pkt.data,
                    link_type,
                );

                if sender.send(record).is_err() {
                    break;
                }
                pkt_num += 1;
            }
        }
        Ok(())
    }

    fn load_pcap<R: Read>(reader: R) -> Result<Vec<PacketRecord>> {
        let mut pcap_reader = PcapReader::new(reader).context("Failed to initialize PCAP reader")?;
        let link_type = u32::from(pcap_reader.header().datalink);

        let mut packets = Vec::new();
        let mut first_ts: Option<f64> = None;
        let mut pkt_num = 1;

        while let Some(pkt) = pcap_reader.next_packet() {
            let pkt = pkt.context("Failed reading pcap packet")?;
            let ts_secs = pkt.timestamp.as_secs();
            let ts_nanos = pkt.timestamp.subsec_nanos();
            let current_ts = ts_secs as f64 + (ts_nanos as f64 / 1_000_000_000.0);

            let rel_time = match first_ts {
                None => {
                    first_ts = Some(current_ts);
                    0.0
                }
                Some(f) => current_ts - f,
            };

            let record = PacketDissector::dissect(
                pkt_num,
                rel_time,
                ts_secs,
                ts_nanos,
                &pkt.data,
                link_type,
            );

            packets.push(record);
            pkt_num += 1;
        }

        Ok(packets)
    }

    fn load_pcapng<R: Read>(reader: R) -> Result<Vec<PacketRecord>> {
        let mut pcapng_reader = PcapNgReader::new(reader).context("Failed to initialize PCAPNG reader")?;

        let mut packets = Vec::new();
        let mut first_ts: Option<f64> = None;
        let mut pkt_num = 1;
        let mut link_type = 1u32; // Default Ethernet

        while let Some(block) = pcapng_reader.next_block() {
            let block = block.context("Failed reading pcapng block")?;
            match block {
                pcap_file::pcapng::Block::InterfaceDescription(idb) => {
                    link_type = u32::from(idb.linktype);
                }
                pcap_file::pcapng::Block::EnhancedPacket(epb) => {
                    let ts_nanos_total = epb.timestamp.as_nanos();
                    let ts_secs = (ts_nanos_total / 1_000_000_000) as u64;
                    let ts_nanos = (ts_nanos_total % 1_000_000_000) as u32;
                    let current_ts = ts_secs as f64 + (ts_nanos as f64 / 1_000_000_000.0);

                    let rel_time = match first_ts {
                        None => {
                            first_ts = Some(current_ts);
                            0.0
                        }
                        Some(f) => current_ts - f,
                    };

                    let record = PacketDissector::dissect(
                        pkt_num,
                        rel_time,
                        ts_secs,
                        ts_nanos,
                        &epb.data,
                        link_type,
                    );

                    packets.push(record);
                    pkt_num += 1;
                }
                pcap_file::pcapng::Block::SimplePacket(spb) => {
                    let record = PacketDissector::dissect(
                        pkt_num,
                        0.0,
                        0,
                        0,
                        &spb.data,
                        link_type,
                    );

                    packets.push(record);
                    pkt_num += 1;
                }
                _ => {}
            }
        }

        Ok(packets)
    }
}
