# Rustshark 🦈

A high-performance terminal user-interface (TUI) for network packet analysis written in Rust, inspired by [Termshark](https://github.com/gcla/termshark) and Wireshark.

![Rustshark](assets/rustshark_preview.png)

## Features

- **Blazingly Fast & Safe**: Written in 100% safe, modern Rust using `ratatui` and `crossterm`.
- **Pure-Rust Packet Dissection**: Runs natively without requiring `tshark` or external dependencies, with full dissection for:
  - Ethernet II & Linux Cooked (SLL)
  - IPv4, IPv6, ARP
  - TCP, UDP, ICMP, ICMPv6
  - Application layer: DNS, HTTP, Telnet, TLS/SSL, DHCP/BOOTP, Raw payload
- **Wireshark / TShark Engine Bridge**: Seamlessly invokes and parses `tshark -T psml` and `tshark -T pdml` when available for 100% Wireshark compatibility.
- **Three-Pane Synchronized UI**:
  - **Pane 1 (Packet List)**: Real-time tabular packet summary (No., Time, Source, Destination, Protocol, Length, Info).
  - **Pane 2 (Packet Details Tree)**: Expandable hierarchical protocol dissection tree with fields and values.
  - **Pane 3 (Hex & ASCII Dump)**: Hexadecimal byte view with ASCII representation and dynamic byte-range highlighting synchronized with selected fields from the details tree.
- **Display Filtering**: Wireshark display filter syntax (`tcp`, `udp`, `http`, `dns`, `ip.addr == ...`, `tcp.port == 80`, `len > 100`, `contains`, `&&`, `||`, `!`).
- **Stream Reassembly & Follow**: Press `s` to follow TCP and UDP conversation streams with distinct coloring for client and server flows, supporting ASCII and Hex modes.
- **Network Conversations**: Press `c` for comprehensive conversation tables across Ethernet, IPv4, IPv6, TCP, and UDP, with one-key filter generation.
- **Multiple Color Themes**: Solarized Dark, Dracula, Default Dark, Default Light, and Base16 (`t` to switch).
- **Packet Marks**: Vim-style marks (`m<a-z>` to set, `'<a-z>` to jump, `''` to jump back).
- **Flexible Layouts**: Full support for vertical stack and side-by-side splits (`|`), and pane maximization (`\`).
- **Live Interface Capture**: Read directly from network interfaces (`-i <interface>`) or PCAP/PCAPNG files (`-r <file>`), including standard input (`-r -`).

---

## Installation & Building

### Prerequisites

- [Rust](https://rustup.rs/) (1.80+ or latest stable)
- `dumpcap` (recommended for non-root live captures, provided by `wireshark-common` or `tshark`)

### Capturing Without Root (`wireshark` Group)

Running network analysis tools with `sudo` is discouraged for security reasons. Like Wireshark and Termshark, Rustshark delegates live capture to `dumpcap`, which relies on Linux capabilities (`cap_net_raw,cap_net_admin`) so non-root users can capture traffic safely:

1. **Install `dumpcap`**:
   - **Ubuntu / Debian / Linux Mint**:
     ```bash
     sudo apt update
     sudo apt install -y wireshark-common
     ```
     When asked *"Should non-superusers be able to capture packets?"*, select **Yes**.  
     *(If already installed or you were not prompted, run: `sudo dpkg-reconfigure wireshark-common`)*
   - **Arch Linux**:
     ```bash
     sudo pacman -S wireshark-cli
     ```
   - **Fedora / RHEL**:
     ```bash
     sudo dnf install wireshark-cli
     ```

2. **Add your user to the `wireshark` group**:
   ```bash
   sudo usermod -aG wireshark $USER
   ```

3. **Activate the group**:
   Group changes only apply to newly opened sessions. Log out and back in, or run this in your active terminal:
   ```bash
   newgrp wireshark
   ```

4. **Verify**:
   ```bash
   dumpcap -D
   ```
   If this outputs your network interfaces without `sudo`, non-root packet capture is ready.

### Build from source

```bash
cd rustshark
cargo build --release
```

The resulting binary will be located at `target/release/rustshark`.

---

## Quick Start

### Inspect a PCAP or PCAPNG file

```bash
rustshark -r capture.pcap
```

### Inspect with an initial display filter

```bash
rustshark -r capture.pcap -Y "tcp.port == 80"
```

### List available capture interfaces

```bash
rustshark -D
```

### Live capture on an interface

```bash
rustshark -i en0
```

### Pipe capture from tcpdump or stdin

```bash
tcpdump -i en0 -w - | rustshark -r -
```

---

## Keybindings & Navigation

| Key | Description |
|-----|-------------|
| **`Tab`** / **`Shift-Tab`** | Cycle active pane (1: Packet List -> 2: Details Tree -> 3: Hex Dump) |
| **`1`**, **`2`**, **`3`** | Jump directly to pane 1, 2, or 3 |
| **`j`** / **`Down`** | Move selection down |
| **`k`** / **`Up`** | Move selection up |
| **`PgDn`** / **`PgUp`** | Scroll page down / page up |
| **`g`** / **`Home`** | Jump to top |
| **`G`** / **`End`** | Jump to bottom |
| **`/`** | Focus display filter bar |
| **`Enter`** | Apply filter (in filter bar) or toggle expand/collapse (in details tree) |
| **`Esc`** | Clear filter / return focus to packet list |
| **`\`** | Maximize / restore current pane |
| **`\|`** | Toggle layout between vertical stack and side-by-side split |
| **`+`** / **`-`** | Increase / decrease relative pane size |
| **`o`** | Sort packet table by next column |
| **`e`** | Expand all nodes in packet structure |
| **`c`** | In main view: open Conversations dialog; In tree view: collapse all nodes |
| **`s`** | Follow TCP / UDP Stream dialog |
| **`p`** | List and select network capture interfaces |
| **`t`** | Cycle themes (Default Dark, Dracula, Solarized Dark, Light, Base16) |
| **`m <a-z>`** | Set mark on selected packet |
| **`' <a-z>`** | Jump to marked packet |
| **`''`** | Jump to previous packet location |
| **`y`** | Copy packet data / summary |
| **`?`** / **`F1`** | Show Help dialog |
| **`q`** / **`Ctrl-C`** | Quit Rustshark |

---

## Display Filter Syntax

Rustshark supports Wireshark display filter expressions:

- **Protocols**: `tcp`, `udp`, `http`, `dns`, `telnet`, `icmp`, `arp`, `ip`, `ipv6`
- **IP Address**: `ip.addr == 192.168.1.1`, `ip.src == 10.0.0.1`, `ip.dst == 172.16.0.2`
- **Port**: `tcp.port == 80`, `udp.port == 53`, `port == 23`
- **Packet Length**: `frame.len > 100`, `len < 64`
- **Text Search**: `frame contains "password"` or plain search `GET /index.html`
- **Logical Operators**: `&&`, `||`, `and`, `or`, `!`

---

## Architecture

```
rustshark/
├── Cargo.toml
├── README.md
├── tests/
│   └── integration_tests.rs   # Comprehensive end-to-end and unit tests
└── src/
    ├── main.rs                # Entry point, CLI flags, terminal setup, panic hook
    ├── lib.rs                 # Library exports
    ├── app.rs                 # Application state, event dispatching, marks, layout
    ├── theme.rs               # Color palettes (Solarized, Dracula, Dark, Light, Base16)
    ├── capture/
    │   ├── mod.rs             # Capture orchestrator
    │   └── iface.rs           # Interface enumeration (system & dumpcap/tshark)
    ├── packet/
    │   ├── mod.rs             # PacketRecord, PacketSummary, TreeNode, DissectionTree
    │   ├── dissector.rs       # Deep packet dissection with byte range tracking
    │   ├── filter.rs          # Wireshark display filter parser & evaluator
    │   ├── stream.rs          # TCP / UDP Stream follow & conversation reassembly
    │   ├── convs.rs           # Multi-protocol conversations analyzer
    │   ├── tshark.rs          # TShark XML PSML & PDML parser
    │   └── loader.rs          # Unified PCAP / PCAPNG file and stdin reader
    └── ui/
        ├── mod.rs             # UI coordinator & layout rendering
        ├── filter_bar.rs      # Filter input widget & live syntax validation
        ├── packet_list.rs     # Tabular packet summary table with sorting
        ├── packet_tree.rs     # Collapsible protocol dissection tree
        ├── hex_dump.rs        # Synchronized hex & ASCII dump with byte highlight
        ├── status_bar.rs      # Status line, statistics, active pane, key hints
        └── modals.rs          # Help, Conversations, Stream Follow, Interface dialogs
```

## License

MIT License.
