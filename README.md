# OpenXDR Agent - eBPF Linux Security Agent

**Goal**: Build a high-performance, tamper-resistant Linux security agent using eBPF for deep kernel visibility and Rust for safe, fast user-space telemetry processing, native SigmaHQ rule evaluation, and advanced threat detection.

---

## Project Status Dashboard

| Component | Status | Description |
|-----------|--------|-------------|
| **Kernel Probes (eBPF)** | **Stable** | Includes `execve`, `execveat`, `openat`, `connect`, LSM (`bprm_check_security`), and kernel modules (`init_module`/`finit_module`). |
| **Detection Engine** | **Stable** | Fully migrated to `null-sigma`. Evaluates live events against the official SigmaHQ corpus. |
| **eBPF Rule Injection** | **Stable** | Parses Sigma `TargetFilename` & `Image` modifiers and loads up to 512 precise filters into kernel memory for fast-path exclusion. |
| **User-Space Agent** | **Stable** | Asynchronous Tokio event multiplexer reading from 5 distinct BPF maps. Emits clean, structured JSON telemetry. |
| **Outputs & Integration** | **In Progress** | Currently emits rich JSON to `stdout`. Architecture planning underway for Syslog or gRPC/HTTPS aggregation. |
| **Static Scanning** | **Pending** | YARA integration for static file/memory scanning is planned. |

---

## Architecture & Workspace

The project is organized as a Cargo workspace with the following members:
- **`openxdr-agent`**: The main user-space application (Root). Responsible for loading Sigma rules, unpacking BPF perf buffers, and emitting JSON telemetry.
- **`openxdr-ebpf`** / **`agent-ebpf`**: The eBPF kernel probes (Kernel space). High-performance hooks written in constrained Rust to filter noise at the kernel boundary.
- **`openxdr-common`**: Shared types and memory structures (`Event` variants) between kernel and user space.

---

## Implementation Roadmap

### Phase 1: Foundation (Completed)
- [x] **Project Setup**: Workspace configuration for `openxdr-common`, `agent-ebpf`, and `agent`.
- [x] **Core Dependencies**: Aya (eBPF framework), Tokio (Async runtime), Serde.
- [x] **Design**: Defined architecture for separate kernel/user memory boundaries.

### Phase 2: Kernel Visibility (eBPF) (Completed)
- [x] **Process Execution**: `sys_enter_execve`, `sys_enter_execveat`. Extracts accurate, space-delimited `argv` strings and binary paths.
- [x] **File Integrity Monitoring (FIM)**: `sys_enter_openat` for tracking sensitive file access/modifications (e.g., `/etc/passwd`).
- [x] **Network Observability**: `sys_enter_connect` to trace outbound IPv4 connections natively.
- [x] **LSM Probes**: `bprm_check_security` for privileged parent-child execution tracking.
- [x] **Kernel Module Tracking**: `sys_enter_init_module` and `sys_enter_finit_module` to catch rootkit loading.

### Phase 3: User-Space Agent & Detection (Completed)
- [x] **Event Loop**: Efficient async reading of `perf_event_array` buffers across all CPUs.
- [x] **SigmaHQ Integration**: Native implementation of `null-sigma` supporting complex modifier parsing (`endswith`, `contains`).
- [x] **eBPF Fast-Path**: Dynamically compiles Sigma blocks into an eBPF `RULES` map (capacity: 512 entries) to drop benign noise entirely inside the kernel.
- [x] **Automated Validation**: `src/scratch/runtime_tester.sh` validates rules locally, generating live runtime coverage reports.

### Phase 4: Outputs & Enterprise Features (Active)
- [x] **Structured Logging**: Clean, formatted JSON telemetry to standard output without C-string `\0` byte pollution.
- [ ] **Remote Transport / Aggregation**: Planning stage for gRPC/HTTPS or Syslog TLS forwarding to a central console.
- [ ] **YARA Static Scanning**: Integration for static payload evaluation on disk and in memory.
- [ ] **Self-Protection**: Prevent agent process termination via advanced LSM hooks.

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
    cargo +nightly build -Z build-std=core --target bpfel-unknown-none --release -p openxdr-ebpf
    ```

2.  **Build Userspace Agent**:
    ```bash
    cargo build --release
    ```

3.  **Run (Root Required)**:
    ```bash
    sudo ./target/release/openxdr-agent
    ```

### Validation & Testing
To verify Sigma rule matching against live kernel hooks, deploy the agent in one terminal and execute the tester in another:
```bash
./src/scratch/runtime_tester.sh
```

---

## Latest Updates
- **[Feature]**: Successfully integrated the `null-sigma` engine, ingesting 50+ official SigmaHQ rules.
- **[Feature]**: Expanded the `RULES` map kernel capacity to 512, safely filtering complex `TargetFilename` permutations.
- **[Feature]**: Added LSM, Module, and Network probes to capture lateral movement and suspicious outbound activity.
- **[Fix]**: Stripped `\0` null-byte padding from JSON payloads, condensing `evt.argv` buffers into precise strings.