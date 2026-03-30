# DroneID Analyser (Rust)

This project analyzes 802.11 beacon frames from a PCAP file to detect DroneID vendor payloads and extract drone telemetry (ID, MAC, GPS position, altitude, speed, heading).

## Features

- Reads packets from a `.pcap` capture file.
- Detects Wi-Fi beacon frames.
- Parses TLV tags (including SSID and vendor-specific fields).
- Extracts DroneID payload when OUI matches `6a:5c:35`.
- Exports detected drones in `json`, `csv`, or `text` format.

## Requirements

- Rust toolchain (stable)
- On Windows: Npcap/WinPcap compatible runtime for `pcap` crate

## Build

```bash
cargo build
```

## CLI Usage

```bash
cargo run -- [OPTIONS]
```

Main options:

- `--pcap <FILE>`: analyze packets from a PCAP file.
- `--interface <INTERFACE>`: live capture mode (currently placeholder in `main.rs`).
- `--cards`: list interfaces (currently prints header only).
- `--filter <FILTER>`: BPF filter (default: `wlan type mgt subtype beacon`).
- `--packet-count <N>`: max packets for live capture mode.
- `--output-format <json|csv|text>`: output format.
- `--output-file <PATH>`: output file path.
- `-v, --verbose`: print extra parsing details.

## Examples

Analyze an offline capture and write JSON:

```bash
cargo run -- --pcap sample.pcap --output-format json --output-file results.json
```

Write CSV output:

```bash
cargo run -- --pcap sample.pcap --output-format csv --output-file results.csv
```

Verbose parsing:

```bash
cargo run -- --pcap sample.pcap -v
```

## Output Fields

Each detected drone includes:

- `id`
- `mac`
- `position.latitude`
- `position.longitude`
- `position.altitude`
- `height`
- `speed`
- `heading`

## Project Structure

- `src/main.rs`: CLI argument parsing and execution flow.
- `src/capture.rs`: packet loop over PCAP data.
- `src/parser.rs`: radiotap/frame/TLV/DroneID payload parsing.
- `src/data.rs`: serializable data models.
- `src/output.rs`: JSON/CSV/Text export.
- `src/lib.rs`: library module exports.

## Current Limitations

- Live capture (`--interface`) is not implemented yet (placeholder message).
- Interface listing (`--cards`) is not implemented yet.
- In `Cargo.toml`, `target.x86_64-pc-windows-msvc.rustflags` is reported as an unused manifest key by Cargo. If linker flags are required, move them to `.cargo/config.toml`.

## Quick Check

Show CLI help:

```bash
cargo run -- --help
```
