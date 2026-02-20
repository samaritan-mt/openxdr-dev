# OpenXDR Agent - Implementation Plan & Status

**Goal**: Build a high-performance, tamper-resistant Linux security agent using eBPF for deep kernel visibility and Rust for safe, fast user-space processing.

## Project Status Dashboard

| Component | Status | Description |
|-----------|--------|-------------|
| **Kernel Probes (eBPF)** | Stable | `execve`, `execveat`, and basic file monitoring implemented. |
| **User-Space Agent** | In Progress | Event loop active, rule engine connected. Refinement needed. |
| **Detection Engine** | In Progress | Basic rule matching works. Aggregation/Correlation pending. |
| **Outputs & Integration** | Pending | JSON logs only. No remote transport or TLS yet. |

---

## Architecture & Workspace

The project is organized as a Cargo workspace with the following members:
- **`openxdr-agent`**: The main user-space application (Root).
- **`openxdr-ebpf`** / **`agent-ebpf`**: The eBPF kernel probes (Kernel space).
- **`openxdr-common`**: Shared types and definitions between kernel and user space.

---

## Implementation Roadmap

### Phase 1: Foundation (Completed)
- [x] **Project Setup**: Workspace configuration for `openxdr-common`, `agent-ebpf`, and `agent`.
- [x] **Core Dependencies**: Aya (eBPF framework), Tokio (Async runtime), Serde.
- [x] **Design**: Defined architecture for separate kernel/user processes.

### Phase 2: Kernel Visibility (eBPF) (Active)
- [x] **Process Execution**: 
    - [x] `sys_enter_execve`: Capture Command, PID, UID.
    - [x] `sys_enter_execveat`: Support different execution paths.
    - [x] Filename Extraction: Robust user-space pointer reading.
- [x] **File Integrity Monitoring (FIM)**:
    - [x] Basic `open` syscall monitoring.
    - [ ] Monitoring modification/write events (critical files like `/etc/passwd`).
    - [ ] Path filtering optimization.

### Phase 3: User-Space Agent & Detection (Active)
- [x] **Event Loop**: Efficient async reading of `perf_event_array` with Tokio.
- [x] **Rule Engine Integration**:
    - [x] `rules.yaml` format design.
    - [x] Loading and parsing rules.
    - [x] In-memory matching against live eBPF events.
- [ ] **Advanced Detection**:
    - [ ] Aggregation/Time-window rules (e.g., "5 failed logins in 1 minute").
    - [ ] Stateful detection.

### Phase 4: Outputs & Enterprise Features (Planned)
- [ ] **Structured Logging**: JSON output to stdout/file (Partially done).
- [ ] **Remote Transport**: TLS implementation for sending alerts to a backend.
- [ ] **Self-Protection**: Prevent agent process termination.

---

## Developer Guide

### Prerequisites
1.  **Rust Nightly**: Required for compiling eBPF programs.
    ```bash
    rustup install nightly
    rustup component add rust-src --toolchain nightly
    ```
2.  **bpf-linker**:
    ```bash
    cargo install bpf-linker
    ```

### Build & Run
1.  **Build eBPF Probes**:
    ```bash
    cargo xtask build-ebpf
    ```
    *Note: If `xtask` is not set up, build directly via `cargo +nightly build -Z build-std=core --target bpfel-unknown-none --release -p openxdr-ebpf`*

2.  **Build Userspace Agent**:
    ```bash
    cargo build
    ```

3.  **Run (Root Required)**:
    ```bash
    sudo ./target/debug/openxdr-agent
    ```

---

## Latest Updates
- **[Feature]**: Connected eBPF event stream to the rule engine.
- **[Feature]**: Added basic File Integrity Monitoring (FIM) hooks.
- **[Fix]**: Resolved `EVENTS` scope issues in eBPF probes.