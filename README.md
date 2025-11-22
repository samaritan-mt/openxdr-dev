## Agent (Rust) – Scope

The first phase of OpenXDR focuses on a Rust-based Linux agent that:

- Reads security-relevant events from `auditd`
- Normalizes and evaluates them against **dynamic rules**
- Produces local findings (logs/syslog) for further processing
- Runs with least privilege and strong hardening

## Roadmap – Rust Agent

- [ ] **Phase 0 – Design & Threat Model**
  - [ ] Define goals, assumptions, and threat model for the agent
  - [ ] Decide deployment model (systemd service) and supported distros

- [ ] **Phase 1 – Project Skeleton**
  - [ ] Create `openxdr-agent` Rust binary crate
  - [ ] Add dependencies for config, logging, and async runtime
  - [ ] Implement config loading and structured logging

- [ ] **Phase 2 – auditd Integration**
  - [ ] Implement event source for auditd (netlink or log tailing)
  - [ ] Normalize audit events into a typed `AuditEvent` struct
  - [ ] Handle malformed events and log safely

- [ ] **Phase 3 – Dynamic Rule Engine**
  - [ ] Design rule format (e.g., `rules.toml` / `rules.yaml`)
  - [ ] Implement rule evaluation against incoming events
  - [ ] Support live rule reload (SIGHUP or file watcher) with validation

- [ ] **Phase 4 – Outputs & Observability**
  - [ ] Implement sinks for matches (log file and/or syslog)
  - [ ] Add a basic status interface (CLI subcommand or optional localhost HTTP)

- [ ] **Phase 5 – Security Hardening**
  - [ ] Run agent under least privilege with hardened systemd unit
  - [ ] Add tests for parsers, rule evaluation, and reload behavior
  - [ ] Document secure configuration and update procedures
