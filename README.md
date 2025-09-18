# Pipe Lion 🦁

**Pipe Lion** is a high-throughput, browser & WASM‑3.0‑based network capture & packet inspection tool. It does for packet traces what Wireshark does, but runs in-browser, is deterministic, sandboxed, and built for modern workflows.

---

## Table of Contents

- [Why Pipe Lion](#why-pipe-lion)  
- [Features](#features)  
- [Architecture](#architecture)  
- [Getting Started](#getting-started)  
  - [Prerequisites](#prerequisites)  
  - [Build & Run (Browser MVP)](#build--run-browser-mvp)  
- [Usage](#usage)  
- [Roadmap](#roadmap)  
- [Contributing](#contributing)  
- [License](#license)  

---

## Why Pipe Lion

- **Portable & browser‑friendly**: No installation required for basic trace analysis; works in modern browsers.  
- **Deterministic & reproducible**: Using the deterministic profile in Wasm 3.0 ensures identical behavior across devices.  
- **Sandboxed & safe**: Parsing, filtering, and protocol decoding happens entirely in WebAssembly.  
- **Extensible**: Plugin/dissector model for adding new protocols without modifying core.  

---

## Features

- Offline support for `.pcap` / `.pcapng` file parsing  
- Packet‑listing, timestamp & interface metadata, raw byte view (hex)  
- Basic protocol decoders for Ethernet, IPv4/IPv6, TCP, UDP  
- Filtering/display of packets by basic predicates (length, time, interface)  
- High performance via Wasm 3.0 features: multiple memories, typed references, potential SIMD/relaxed vector paths  
- UI: drag‑and‑drop trace upload, table view, hex view, header trees  

---

## Architecture

```
       +------------------+
       |  Web UI (React)  |
       +------------------+
               ↕ WebAssembly
       +------------------+
       |  Core Parser &   |
       |  Dissector Logic |
       |  (Rust → Wasm‑3.0)|
       +------------------+
               ↕ Multiple Memories
       | - Raw bytes buffer (mem0)     |
       | - Index / metadata buffer      |
       | - Parsed headers / fields buf  |
       +------------------+
```

Key pieces:
- **Core library** in Rust, compiled to `wasm32-unknown-unknown` for browser, and `wasm32-wasi` for CLI/stand‑alone.
- **Memory layout** using multiple memories to separate raw data, index, parsed fields.
- **Plugin / component model** for protocol dissectors using typed refs and `call_ref`.
- **Deterministic profile**: fallback behavior and strict modes to ensure reproducibility.

---

## Getting Started

### Prerequisites

- Rust toolchain  
- Node.js / npm / yarn / pnpm (for web UI)  
- Wasm target added:  
  ```bash
  rustup target add wasm32-unknown-unknown
  rustup target add wasm32-wasi
  ```

### Build & Run (Browser MVP)

1. Clone repository:  
   ```bash
   git clone https://github.com/yourusername/pipe-lion.git
   cd pipe-lion
   ```

2. Build Rust core to Wasm:  
   ```bash
   cd core
   cargo build --release --target wasm32-unknown-unknown
   ```

3. Copy / link `core.wasm` into `webapp/dist/` (or configure your build tool to do so).

4. Start the web UI:  
   ```bash
   cd webapp
   pnpm install    # or npm / yarn
   pnpm dev        # or npm run dev
   ```

5. Open your browser at `http://localhost:3000` (or whatever port), upload a `.pcap`/`.pcapng` file, and enjoy.

---

## Usage

| Action                  | Description |
|--------------------------|-------------|
| Drop a trace file        | Upload `.pcap`/`.pcapng` and get packet list with timestamps & lengths |
| View raw bytes           | Hex‑dump view of each packet |
| Header tree view         | Expand Ethernet/IP/TCP layers & header fields |
| Basic filtering          | Length, time range, interface, link type etc. |
| Export data              | JSON or other formats for downstream processing |

---

## Roadmap

- **v0.x**  
  ‑ More complete `.pcap` / `.pcapng` support (options, variants, timestamp units)  
  ‑ Add more protocol dissectors: DNS, HTTP, TLS/QUIC  
  ‑ Toggle between deterministic & fast (SIMD) modes  

- **v1.0**  
  ‑ Live capture via sidecar on desktop (Rust native) forwarding frames to browser UI  
  ‑ Plugin ABI & component model for external dissectors  

- **v2.0+**  
  ‑ Standalone CLI via WASI for batch trace processing  
  ‑ Advanced features: session reassembly, decryption (TLS with secrets), filtering language, large‑trace optimizations  
