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
  - [x] Create `openxdr-agent` Rust binary crate
  - [x] Add dependencies for config, logging, and async runtime
  - [x] Implement config loading and structured logging (via `agent::Config` and `tracing_subscriber`)

- [ ] **Phase 2 – auditd Integration**
  - [ ] Implement event source for auditd (netlink or log tailing)
  - [ ] Normalize audit events into a typed `AuditEvent` struct
  - [ ] Handle malformed events and log safely

- [ ] **Phase 3 – Dynamic Rule Engine**
  - [x] Design rule format (YAML in `src/lib/alert-rules.yaml`)
  - [ ] Implement rule evaluation against incoming events
  - [ ] Support live rule reload (SIGHUP or file watcher) with validation

- [ ] **Phase 4 – Outputs & Observability**
  - [ ] Implement sinks for matches (log file and/or syslog)
  - [ ] Add a basic status interface (CLI subcommand or optional localhost HTTP)

- [ ] **Phase 5 – Security Hardening**
  - [ ] Run agent under least privilege with hardened systemd unit
  - [ ] Add tests for parsers, rule evaluation, and reload behavior
  - [ ] Document secure configuration and update procedures


## Dynamic Rules & Alerts (Agent)

The Rust agent applies a dynamic set of detection rules defined in a YAML file and emits JSON alerts whenever a rule matches.

- Rules are defined in `rules.yaml` as a classical list of rule objects under `rules:`.
- Each rule can be:
  - A single-event rule (`match` block).
  - An aggregation rule (`aggregation` block) that triggers when a threshold is met over a time window.
- On every match, the agent emits a JSON payload with:
  - Rule metadata (id, description, severity).
  - Host and timestamp.
  - Whether the match is aggregated or single-event.
  - Normalized event data (e.g., user, process, syscall, paths).

Planned tasks:

- [ ] Design and implement `AuditEvent` (rule YAML schema implemented in `src/lib/alert-rules.yaml`).
- [x] Implement YAML rule loading and validation (basic loading via `agent::rules::load_rules`).
- [ ] Implement real-time audit event ingestion and normalization.
- [ ] Implement rule engine (single-event and aggregation).
- [ ] Emit JSON alerts to configurable sinks (stdout/file/syslog/HTTP) (currently stdout only).
- [ ] Support live rule reload without restarting the agent.
