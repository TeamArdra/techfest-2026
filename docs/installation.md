# AegisFlight — Multi-OS Installation & Configuration Reference

This guide provides concise, OS-specific installation instructions for **Windows**, **macOS**, **Linux**, and **Onboard Drone Companion Computers** (Raspberry Pi, NVIDIA Jetson).

---

## 1. System Requirements

- **Python**: $\ge 3.11$ (tested on 3.11, 3.12, and 3.13)
- **Node.js**: $\ge 18$ + npm (required for the GCS dashboard)
- **Rust**: $\ge 1.80$ + Cargo (required for the native Tauri desktop GCS and zero-allocation frame sanitizer)
- **Operating Systems**:
  - **Windows 10 / 11** (x64 / ARM64)
  - **macOS 12+** (Apple Silicon M-Series and Intel)
  - **Linux** (Ubuntu 22.04/24.04, Debian 12, Fedora 39/40, Arch Linux)
  - **Single-Board Computers** (Raspberry Pi OS 64-bit, JetPack 5.x/6.x)
- **Hardware Resources**: $\ge 512\text{ MB}$ RAM, no GPU required.

---

## 2. Installation by Operating System

### A. Windows 10 & 11 (PowerShell)

1. **Install Prerequisites**:
   ```powershell
   winget install Python.Python.3.11
   winget install OpenJS.NodeJS.LTS
   winget install Rustlang.Rustup
   ```
   *(Ensure "Add python.exe to PATH" is checked during Python installation.)*

2. **Virtual Environment & Package**:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   pip install -e ".[dev]"
   ```

3. **Frontend & Backend Launch**:
   ```powershell
   npm --prefix frontend install
   npm --prefix frontend run build
   aegis serve --defense-mode active-ips --port 8000
   ```

4. **(Optional) Native Desktop Application**:
   ```powershell
   cd frontend
   cargo tauri dev
   ```

---

### B. macOS (Apple Silicon & Intel)

1. **Install Prerequisites**:
   ```bash
   xcode-select --install
   brew install python@3.11 node rust
   ```

2. **Virtual Environment & Package**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

3. **Frontend & Backend Launch**:
   ```bash
   npm --prefix frontend install
   npm --prefix frontend run build
   aegis serve --defense-mode active-ips --port 8000
   ```

4. **Native Desktop Application**:
   ```bash
   cd frontend
   cargo tauri dev
   ```

---

### C. Linux (Ubuntu / Debian / Fedora)

1. **Install System Dependencies & Build Tools**:
   ```bash
   # Ubuntu / Debian:
   sudo apt update && sudo apt install -y \
     python3-venv python3-pip python3-dev build-essential git curl \
     libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf libssl-dev libayatana-appindicator3-dev

   # Node.js LTS:
   curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
   sudo apt install -y nodejs

   # Rust:
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
   source "$HOME/.cargo/env"
   ```

2. **Grant Serial Port Permissions** (for USB telemetry radios & flight controllers):
   ```bash
   sudo usermod -a -G dialout $USER
   # Log out and back in for changes to take effect
   ```

3. **Virtual Environment & Package**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

4. **Frontend & Backend Launch**:
   ```bash
   npm --prefix frontend install
   npm --prefix frontend run build
   aegis serve --defense-mode active-ips --port 8000
   ```

---

### D. Onboard Companion SBCs (Raspberry Pi / NVIDIA Jetson)

1. **Raspberry Pi OS (Bookworm 64-bit)**:
   ```bash
   # Enable hardware UART on GPIO pins (Pins 8 & 10):
   sudo raspi-config
   # Select: Interface Options -> Serial Port
   # Console shell: NO, Hardware enable: YES
   sudo reboot

   # Install & start daemon:
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   aegis serve --defense-mode active-ips --topology auto --port 8000
   ```

2. **NVIDIA Jetson (JetPack 5.x / 6.x)**:
   - Connect via hardware UART `/dev/ttyTHS1` (J41 header) or USB adapter `/dev/ttyUSB0`.
   - HAL auto-detects Jetson hardware and tunes the latency budget to $18\text{ ms}$.

---

## 3. Verification & Validation Commands

Confirm installation integrity across any platform:

```bash
# 1. 8-Suite Automated Stage 2 Prevention & HAL Audit (~40 ms):
python scripts/verify_stage2.py

# 2. Fast unit test suite (< 1 s):
pytest tests/unit/test_mitigation.py tests/unit/test_hal.py -q

# 3. Full test suite (650+ tests):
pytest

# 4. Code quality & linting:
ruff check src tests scripts
```
