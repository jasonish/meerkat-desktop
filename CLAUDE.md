# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Development Commands

### Frontend Development

```bash
# Install dependencies
npm install

# Start development server (localhost:1420)
npm run dev

# Build frontend for production
npm run build

# Preview production build
npm run serve
```

### Tauri Development

```bash
# Run full app in development mode
npm run tauri dev

# Build production executable (.msi installer on Windows)
npm run tauri build
```

### Rust Development

```bash
# Build Rust backend
cd src-tauri && cargo build

# Run Rust tests (none currently)
cd src-tauri && cargo test

# Check Rust code for errors
cd src-tauri && cargo check

# Format Rust code
cd src-tauri && cargo fmt
```

## Architecture Overview

This is a Windows-only Tauri desktop application that provides a graphical control panel for managing Suricata (network threat detection engine).

### Key Features

- Install Suricata and NPCap with progress tracking
- Select network interfaces by GUID for packet capture
- Start/stop Suricata with real-time output monitoring
- Automatic process cleanup on exit
- Suricata-themed UI (orange/black)

### Project Structure

- `/src/` - Frontend SolidJS application

  - `App.tsx` - Main UI component with all Suricata controls
  - `App.css` - Styling with Suricata brand colors
  - Uses reactive signals for state management
  - Real-time event listeners for backend communication

- `/src-tauri/` - Rust backend
  - `src/lib.rs` - Core logic with Tauri commands:
    - `get_network_interfaces` - Parses ipconfig/getmac for adapter info
    - `install_suricata/install_npcap` - Downloads and launches installers
    - `check_suricata_status` - Checks if process is running
    - `start/stop_suricata_with_output` - Process management with output streaming
  - Uses tokio for async operations
  - Shared state for process handle management

### Frontend-Backend Communication

- Frontend calls backend via `invoke()` from `@tauri-apps/api/core`
- Backend emits events:
  - `download-progress-suricata/npcap` - Installation progress
  - `suricata-output` - Real-time process output
- Window close event triggers automatic Suricata cleanup

### Important Implementation Details

1. **Network Interface Selection**: Displays adapter name, IP, and GUID (required for packet capture)
2. **Process Management**: Force terminates with `taskkill /F`, maintains process handle in shared state
3. **Output Streaming**: Keeps last 1000 lines in memory, auto-scrolls UI
4. **File Paths**: Expects Suricata at `C:\Program Files\Suricata`, logs at `%USERPROFILE%\.meerkat-desktop\log`
5. **No Admin Mode**: Runs without elevated privileges

### Application Icon

The application should use a cute meerkat face for its icon, reflecting the "Suricata" (meerkat) theme.

## Development Notes

- Windows-only due to Suricata installation paths and network interface handling
- Marked as "EXPERIMENTAL" in the UI
- No test suite currently implemented
- Basic CSP disabled in tauri.conf.json for flexibility

## Claude Guidance

- Never run a development server.
