use rustshark::packet::convs::Conversations;
use rustshark::packet::filter::FilterExpr;
use rustshark::packet::loader::PacketLoader;
use rustshark::packet::stream::StreamReassembly;
use std::path::Path;

#[test]
fn test_cli_help() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--bin", "rustshark", "--", "--help"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run cargo run --bin rustshark -- --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.to_lowercase().contains("rustshark"));
    assert!(stdout.contains("--read"));
    assert!(stdout.contains("--interface"));
    assert!(stdout.contains("--display-filter"));
}

#[test]
fn test_list_interfaces() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--bin", "rustshark", "--", "-D"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run cargo run --bin rustshark -- -D");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Available capture interfaces:"));
}

#[test]
fn test_load_sample_pcap() {
    let pcap_path = "../termshark/scripts/pcaps/telnet-cooked.pcap";
    assert!(Path::new(pcap_path).exists(), "Sample pcap file must exist");

    let packets = PacketLoader::load_from_file(pcap_path).expect("Failed to load sample pcap");
    assert!(!packets.is_empty(), "Pcap should have packets");

    println!("Loaded {} packets", packets.len());

    // Verify first packet structure
    let first = &packets[0];
    assert_eq!(first.summary.num, 1);
    assert!(first.summary.length > 0);
    assert!(!first.tree.root_nodes.is_empty());

    // Verify Frame and Link Layer
    let frame_node = &first.tree.root_nodes[0];
    assert!(frame_node.title.starts_with("Frame 1:"));
    assert_eq!(frame_node.byte_range, Some(0..first.raw_data.len()));
}

#[test]
fn test_display_filter_engine() {
    let pcap_path = "../termshark/scripts/pcaps/telnet-cooked.pcap";
    let packets = PacketLoader::load_from_file(pcap_path).expect("Failed to load sample pcap");

    // Test protocol filter: TCP
    let filter_tcp = FilterExpr::parse("tcp").expect("Valid TCP filter");
    let tcp_matches: Vec<_> = packets.iter().filter(|p| filter_tcp.matches(p)).collect();
    assert!(!tcp_matches.is_empty(), "Should match TCP packets");

    // Test protocol filter: Telnet
    let filter_telnet = FilterExpr::parse("telnet").expect("Valid Telnet filter");
    let telnet_matches: Vec<_> = packets.iter().filter(|p| filter_telnet.matches(p)).collect();
    assert!(!telnet_matches.is_empty(), "Should match Telnet packets");

    // Test port filter: 23
    let filter_port23 = FilterExpr::parse("tcp.port == 23").expect("Valid port filter");
    let port_matches: Vec<_> = packets.iter().filter(|p| filter_port23.matches(p)).collect();
    assert_eq!(tcp_matches.len(), port_matches.len());

    // Test IP filter
    let first_ip = &packets[0].summary.src;
    let filter_ip = FilterExpr::parse(&format!("ip.addr == {}", first_ip)).expect("Valid IP filter");
    let ip_matches: Vec<_> = packets.iter().filter(|p| filter_ip.matches(p)).collect();
    assert!(!ip_matches.is_empty());

    // Test boolean combination (AND, NOT)
    let filter_complex = FilterExpr::parse("tcp and !udp").expect("Valid complex filter");
    let complex_matches: Vec<_> = packets.iter().filter(|p| filter_complex.matches(p)).collect();
    assert_eq!(complex_matches.len(), tcp_matches.len());
}

#[test]
fn test_stream_follow() {
    let pcap_path = "../termshark/scripts/pcaps/telnet-cooked.pcap";
    let packets = PacketLoader::load_from_file(pcap_path).expect("Failed to load sample pcap");

    // Find a telnet packet with payload
    let telnet_pkt = packets
        .iter()
        .find(|p| p.summary.protocol == "Telnet")
        .expect("Should find at least one Telnet packet");

    let stream = StreamReassembly::reassemble_for_packet(telnet_pkt, &packets)
        .expect("Should reassemble stream for Telnet conversation");

    assert!(!stream.chunks.is_empty());
    assert!(stream.total_client_bytes > 0 || stream.total_server_bytes > 0);
    println!(
        "Stream {} <-> {}: {} chunks, {} client bytes, {} server bytes",
        stream.client_endpoint,
        stream.server_endpoint,
        stream.chunks.len(),
        stream.total_client_bytes,
        stream.total_server_bytes
    );
}

#[test]
fn test_conversations_analysis() {
    let pcap_path = "../termshark/scripts/pcaps/telnet-cooked.pcap";
    let packets = PacketLoader::load_from_file(pcap_path).expect("Failed to load sample pcap");

    let convs = Conversations::build(&packets);
    assert!(!convs.tcp_convs.is_empty(), "Should detect TCP conversations");
    assert!(!convs.ip4_convs.is_empty(), "Should detect IPv4 conversations");

    let tcp_conv = &convs.tcp_convs[0];
    assert!(tcp_conv.total_pkts > 0);
    assert!(tcp_conv.total_bytes > 0);

    // Verify filter generation from conversation
    let generated_filter = tcp_conv.to_filter(rustshark::packet::convs::ConvType::TCP);
    assert!(generated_filter.contains("tcp.port"));
    let parsed_filter = FilterExpr::parse(&generated_filter);
    assert!(parsed_filter.is_ok(), "Generated conversation filter must be valid");
}

#[test]
fn test_load_streaming() {
    let pcap_path = "../termshark/scripts/pcaps/telnet-cooked.pcap";
    let file = std::fs::File::open(pcap_path).expect("Failed to open sample pcap");
    let (tx, rx) = std::sync::mpsc::channel();

    let handle = std::thread::spawn(move || {
        PacketLoader::load_streaming(file, tx).expect("load_streaming should succeed");
    });

    let mut count = 0;
    while let Ok(pkt) = rx.recv() {
        assert_eq!(pkt.summary.num, count + 1);
        count += 1;
    }
    handle.join().unwrap();
    assert_eq!(count, 92);
}

#[test]
fn test_dumpcap_pcapng_streaming() {
    if std::process::Command::new("dumpcap").arg("-v").output().is_err() {
        return; // Skip if dumpcap not installed
    }

    let mut child = match std::process::Command::new("dumpcap")
        .args(["-i", "en0", "-c", "2", "-w", "-", "-Q"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return, // Permission or interface unavailable
    };

    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => return,
    };

    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let _ = PacketLoader::load_streaming(stdout, tx);
    });

    let _ = child.wait();
    let _ = handle.join();

    let mut count = 0;
    while let Ok(pkt) = rx.try_recv() {
        assert!(pkt.summary.num >= 1);
        count += 1;
    }
    println!("Dumpcap streaming test captured {} live packets", count);
}


