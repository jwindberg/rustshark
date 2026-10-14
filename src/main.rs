mod app;
mod capture;
mod packet;
mod theme;
mod ui;

use anyhow::{Context, Result};
use app::App;
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use packet::loader::PacketLoader;
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::{stdout, IsTerminal};
use std::panic;
use std::path::Path;
use std::time::Duration;
use theme::ThemeVariant;

/// Rustshark: A high-performance terminal user-interface for network packet analysis inspired by Termshark & Wireshark.
#[derive(Parser, Debug)]
#[command(name = "rustshark", version = "0.1.0", about = "Terminal UI for packet analysis")]
struct Cli {
    /// Pcap file or filter to read
    #[arg(value_name = "FilterOrPcap")]
    pcap_or_filter: Option<String>,

    /// Read packet data from file / fifo (use '-' for stdin)
    #[arg(short = 'r', long = "read")]
    read_file: Option<String>,

    /// Interface(s) to read / capture from
    #[arg(short = 'i', long = "interface")]
    interface: Option<String>,

    /// Write raw packet data to outfile
    #[arg(short = 'w', long = "write")]
    write_file: Option<String>,

    /// Apply display filter
    #[arg(short = 'Y', long = "display-filter")]
    display_filter: Option<String>,

    /// Apply capture filter
    #[arg(short = 'f', long = "capture-filter")]
    capture_filter: Option<String>,

    /// Print a list of interfaces on which rustshark can capture
    #[arg(short = 'D', long = "list-interfaces")]
    list_interfaces: bool,

    /// Color theme: default-dark, dracula, solarized, light, base16
    #[arg(short = 't', long = "theme", default_value = "default-dark")]
    theme: String,
}

fn setup_panic_hook() {
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen, DisableMouseCapture);
        default_hook(panic_info);
    }));
}

fn spawn_live_capture(
    iface: &str,
    filter: Option<&str>,
    sender: std::sync::mpsc::Sender<crate::packet::PacketRecord>,
) -> (Option<std::process::Child>, Option<String>) {
    let mut cmd = if std::process::Command::new("dumpcap").arg("-v").output().is_ok() {
        let mut c = std::process::Command::new("dumpcap");
        c.args(["-i", iface, "-w", "-"]);
        if let Some(cf) = filter {
            c.args(["-f", cf]);
        }
        c.stdout(std::process::Stdio::piped());
        c.stderr(std::process::Stdio::piped());
        c
    } else if std::process::Command::new("tcpdump").arg("--version").output().is_ok() {
        let mut c = std::process::Command::new("tcpdump");
        c.args(["-i", iface, "-w", "-", "-U"]);
        if let Some(cf) = filter {
            c.args(["-f", cf]);
        }
        c.stdout(std::process::Stdio::piped());
        c.stderr(std::process::Stdio::piped());
        c
    } else {
        return (None, Some("Neither dumpcap nor tcpdump found for live capture".to_string()));
    };

    match cmd.spawn() {
        Ok(mut child) => {
            // Check quickly if child exited immediately with error
            std::thread::sleep(std::time::Duration::from_millis(150));
            if let Ok(Some(status)) = child.try_wait() {
                let mut err_msg = format!("Capture exited with status: {}", status);
                if let Some(mut stderr) = child.stderr.take() {
                    let mut s = String::new();
                    let _ = std::io::Read::read_to_string(&mut stderr, &mut s);
                    if !s.trim().is_empty() {
                        err_msg = s.trim().lines().next().unwrap_or(&s).to_string();
                    }
                }
                if err_msg.to_lowercase().contains("permission") || err_msg.to_lowercase().contains("bpf") {
                    err_msg = format!("Permission denied on {}: run with 'sudo ./rustshark'", iface);
                }
                return (None, Some(err_msg));
            }

            if let Some(stdout) = child.stdout.take() {
                std::thread::spawn(move || {
                    let _ = PacketLoader::load_streaming(stdout, sender);
                });
            }
            (Some(child), None)
        }
        Err(e) => (None, Some(format!("Failed to start capture: {}", e))),
    }
}

fn main() -> Result<()> {
    setup_panic_hook();

    let cli = Cli::parse();

    // 1. Check if -D (list interfaces) was requested
    if cli.list_interfaces {
        let ifaces = capture::list_interfaces();
        println!("Available capture interfaces:");
        for iface in ifaces {
            println!("{}. {} ({})", iface.index, iface.name, iface.description);
        }
        return Ok(());
    }

    // 2. Check if piped input is arriving on stdin (e.g. tcpdump ... | rustshark)
    let stdin_has_data = !std::io::stdin().is_terminal();

    // 3. Determine file or source to read
    let (pcap_path, initial_filter) = if stdin_has_data && cli.read_file.is_none() && cli.interface.is_none() {
        (Some("-".to_string()), cli.display_filter.clone().or(cli.pcap_or_filter.clone()))
    } else {
        match (&cli.read_file, &cli.pcap_or_filter) {
            (Some(rf), Some(f)) => (Some(rf.clone()), Some(f.clone())),
            (Some(rf), None) => (Some(rf.clone()), cli.display_filter.clone()),
            (None, Some(arg)) => {
                if Path::new(arg).exists() || arg == "-" {
                    (Some(arg.clone()), cli.display_filter.clone())
                } else {
                    (None, Some(arg.clone()))
                }
            }
            (None, None) => (None, cli.display_filter.clone()),
        }
    };

    let theme_variant = ThemeVariant::from_name(&cli.theme);

    // 4. Load packets or start live capture on default interface
    let (source_name, packets, live_child, packet_rx, init_status) = if let Some(path) = pcap_path {
        let pkts = PacketLoader::load_from_file(&path)
            .with_context(|| format!("Error loading pcap from {}", path))?;
        (path, pkts, None, None, None)
    } else {
        // If interface was specified with -i, use it; otherwise default to default_interface() (like Termshark does)
        let iface = cli.interface.clone().unwrap_or_else(capture::default_interface);
        let (tx, rx) = std::sync::mpsc::channel();
        let (child, err) = spawn_live_capture(&iface, cli.capture_filter.as_deref(), tx);
        let status = err.or_else(|| Some(format!("Listening on {} (Live capture active)", iface)));
        (format!("Interface: {}", iface), Vec::new(), child, Some(rx), status)
    };

    // 5. Initialize Application State
    let mut app = App::new(source_name, packets, theme_variant);
    if let Some(msg) = init_status {
        app.status_message = Some(msg);
    }
    if let Some(filter) = initial_filter {
        app.filter_input = filter;
        app.apply_filter();
    }

    // 6. Setup Terminal
    enable_raw_mode().context("Failed to enable raw mode")?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .context("Failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("Failed to create terminal")?;

    // 7. Run Event Loop
    let tick_rate = Duration::from_millis(50);
    let mut running = true;

    while running {
        // Poll for newly arrived packets if live capturing
        if let Some(rx) = &packet_rx {
            while let Ok(pkt) = rx.try_recv() {
                app.add_packet(pkt);
            }
        }

        terminal.draw(|f| ui::render_ui(f, &app))?;

        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                running = app.handle_key(key);
            }
        }
    }

    // 8. Cleanup Terminal and live capture child on exit
    if let Some(mut child) = live_child {
        let _ = child.kill();
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    println!("Rustshark exited cleanly.");
    Ok(())
}
