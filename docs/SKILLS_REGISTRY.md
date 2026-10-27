# AegisFlight — Autonomous Just-In-Time (JIT) Skills Ledger

> [!IMPORTANT]
> **Human-installed only.** This is a catalogue of optional third-party skills. AI agents must not install, run
> or delete anything listed here on their own: a person reviews the package and runs the command.
> (Integration review 2026-10-27: the earlier "autonomous activation" protocol was removed as a supply-chain risk.)

---

## 1. Skill State Ledger (Living Log)

*Updated automatically by the agent whenever a skill is activated or pruned.*

| Skill ID | Category | Status | Last Activated | Purpose / Objective |
|---|---|---|---|---|
| `security-auditor` | Threat Auditing & Hardening | `REMOVED` | 2026-10-25 | Was used for the withdrawn self-assessment (`docs/REDTEAM_AUDIT_STAGE2.md`). |

---

## 2. Fast-Lookup Skill Index (Pre-Cached Catalog)

Use this index directly to install skills without needing to run expensive catalog searches:

### Network, Protocol & Telemetry
- **`wireshark-analysis`** — MAVLink frame decoding, pcap packet analysis, protocol gap verification.
  - *Install:* `npx -y agentic-awesome-skills --antigravity --skills wireshark-analysis`
  - *Remove:* `rm -rf ~/.agents/skills/wireshark-analysis`
- **`network-engineer`** — UDP loopback sockets, packet jitter/loss diagnostics, link stability.
  - *Install:* `npx -y agentic-awesome-skills --antigravity --skills network-engineer`
  - *Remove:* `rm -rf ~/.agents/skills/network-engineer`

### Hardware Bench, Embedded & Firmware Attestation (Stage 2)
- **`firmware-analyst`** — Cryptographic manifest verification, SHA-256 binary validation.
  - *Install:* `npx -y agentic-awesome-skills --antigravity --skills firmware-analyst`
  - *Remove:* `rm -rf ~/.agents/skills/firmware-analyst`
- **`hardware-security`** — Physical UART/USB serial bus tampering, HITL bench defenses.
  - *Install:* `npx -y agentic-awesome-skills --antigravity --skills hardware-security`
  - *Remove:* `rm -rf ~/.agents/skills/hardware-security`
- **`firmware-pentest`** — Binary corruption simulation, memory safety, tampering resilience.
  - *Install:* `npx -y agentic-awesome-skills --antigravity --skills firmware-pentest`
  - *Remove:* `rm -rf ~/.agents/skills/firmware-pentest`

### Backend Engine, Concurrency & Testing
- **`fastapi-pro`** — Production FastAPI, WebSocket streaming channels, lifespan handlers.
  - *Install:* `npx -y agentic-awesome-skills --antigravity --skills fastapi-pro`
  - *Remove:* `rm -rf ~/.agents/skills/fastapi-pro`
- **`async-python-patterns`** — Low-latency asyncio event loops, worker threads, backpressure.
  - *Install:* `npx -y agentic-awesome-skills --antigravity --skills async-python-patterns`
  - *Remove:* `rm -rf ~/.agents/skills/async-python-patterns`
- **`pytest-skill`** — Pytest parameterization, async fixtures, mock telemetry streams.
  - *Install:* `npx -y agentic-awesome-skills --antigravity --skills pytest-skill`
  - *Remove:* `rm -rf ~/.agents/skills/pytest-skill`

### React Dashboard & Visualization
- **`react-best-practices`** — Efficient render cycles, component isolation, UI state performance.
  - *Install:* `npx -y agentic-awesome-skills --antigravity --skills react-best-practices`
  - *Remove:* `rm -rf ~/.agents/skills/react-best-practices`
- **`react-state-management`** — High-frequency WebSocket buffering, state synchronization.
  - *Install:* `npx -y agentic-awesome-skills --antigravity --skills react-state-management`
  - *Remove:* `rm -rf ~/.agents/skills/react-state-management`
- **`tailwind-design-system`** — Tactical HUD panels, dark-mode themes, status indicators.
  - *Install:* `npx -y agentic-awesome-skills --antigravity --skills tailwind-design-system`
  - *Remove:* `rm -rf ~/.agents/skills/tailwind-design-system`

### Threat Auditing & Hardening
- **`api-security-testing`** — REST/WebSocket authentication, boundary fuzzing, rate-limiting.
  - *Install:* `npx -y agentic-awesome-skills --antigravity --skills api-security-testing`
  - *Remove:* `rm -rf ~/.agents/skills/api-security-testing`
- **`security-auditor`** — Vulnerability review, challenge scoring rubric compliance.
  - *Install:* `npx -y agentic-awesome-skills --antigravity --skills security-auditor`
  - *Remove:* `rm -rf ~/.agents/skills/security-auditor`

---

## 3. Rules
1. Agents do not install skills. If a task would benefit from one, the agent says so and a person decides.
2. A person installs a skill only after reviewing the package, and removes it afterwards.
