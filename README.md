## OpenXDR Agent (Rust + eBPF)

OpenXDR is a high-performance Linux security agent that leverages **eBPF (Extended Berkeley Packet Filter)** for deep kernel-level visibility. It is designed to capture security-relevant events with minimal overhead and high tamper resistance.

### Key Features
- **eBPF-based Event Capture**: Uses kernel tracepoints (`sys_enter_execve`, `sys_enter_execveat`) to capture process executions directly from the kernel.
- **Safe & Fast**: Written in Rust using the [Aya](https://aya-rs.dev/) framework for strict type safety and memory safety.
- **Robustness**: Handles high-throughput event streams and gracefully handles kernel memory reads.
- **Hardening**: Runs as a separate process from the kernel logic, maintaining stability.

## Architecture

The project consists of two main components:
1.  **Kernel Probes (`openxdr-ebpf`)**: eBPF programs written in Rust that attach to kernel tracepoints and forward events to user space via `perf_event_array`.
2.  **User-Space Agent**: A Rust application that loads the eBPF programs, consumes events, applies normalization, and (planned) evaluates detection rules.

## Roadmap

- [ ] **Phase 0 – Design & Foundation**
  - [x] Define goals: eBPF-based monitoring for performance and evasion resistance.
  - [x] Set up project structure with workspace support (`openxdr-common`, `agent-ebpf`, `agent`).

- [ ] **Phase 1 – Kernel Visibility (eBPF)**
  - [x] Implement standard `execve` monitoring (PID, UID, Command, Filename).
  - [x] Implement `execveat` support for modern execution flows.
  - [x] Robust filename reading (handling user vs. kernel space pointers).

- [ ] **Phase 2 – User-Space Agent**
  - [x] Load and attach eBPF programs using Aya.
  - [x] Efficient async event reading loop (Tokio).
  - [x] Basic event parsing and logging to stdout.

- [ ] **Phase 3 – Dynamic Rules & Alerting**
  - [x] Design initial rule format (`rules.yaml`).
  - [x] Implement basic config and rule loading.
  - [ ] **Next**: Connect eBPF event stream to the rule engine for real-time detection.
  - [ ] Implement aggregation rules (time-window based).

- [ ] **Phase 4 – Outputs & Integration**
  - [ ] Structured JSON logging / Syslog integration.
  - [ ] TLS transport to backend/console.

## Legacy Note
*Earlier concepts involving `auditd` have been superseded by the direct eBPF approach to ensure better performance and granular control.*
*The choice of ebpf was made regarding the difficulties to listen to auditd events from the source*

## TODO

- [ ]  Implement File Integrity Monitoring (FIM)
  - [ ] Using eBPF listen for any file modification for critical files such as /etc/passwd, /etc/shadow, /etc/group, /etc/gshadow, /etc/sudoers, /etc/sudoers.d/*
  - [ ]  
 