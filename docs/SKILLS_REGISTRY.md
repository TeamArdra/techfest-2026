# AegisFlight — Autonomous Just-In-Time (JIT) Skills Ledger

> [!IMPORTANT]
> **Autonomous Agent Protocol (Strict Token & Context Economy):**
> 1. **Zero Turn Overhead:** Do **NOT** read or inject this file on regular turns. Only access it on-demand when activating or pruning a skill.
> 2. **Autonomous Activation:** The agent automatically identifies when a specialized skill is needed to maximize code quality, architectural integrity, or security for a specific subtask.
> 3. **Fast Local Lookup:** Check the verified index below first before querying remote catalogs to eliminate lookup latency and token waste.
> 4. **Single-Skill Installation:** Install only the exact skill needed (`npx -y agentic-awesome-skills --antigravity --skills <id>`).
> 5. **Automatic Teardown:** Once the workstream/objective is tested and complete, immediately uninstall the skill (`rm -rf ~/.agents/skills/<id>`) to return context tokens to baseline.

---

## 1. Skill State Ledger (Living Log)

*Updated automatically by the agent whenever a skill is activated or pruned.*

| Skill ID | Category | Status | Last Activated | Purpose / Objective |
|---|---|---|---|---|
| `security-auditor` | Threat Auditing & Hardening | `COMPLETED / PRUNED` | 2026-10-25 16:30 | Formal red-team scoring audit against IIT Bombay PUSHPAK Stage 2 rubric (Score: 92/100). Skill pruned to restore token baseline. |

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

## 3. Autonomous Execution Rules for the Assistant

1. **Autonomous Decision:** When encountering a complex or specialized task, evaluate if domain guidance is required. If standard codebase patterns suffice, do not load any skill.
2. **Instant Local Command:** Check the index above. If the skill is indexed, install it immediately via shell command (no catalog web/search needed).
3. **If Non-Indexed Skill Needed:** Run a minimal, narrow query:
   `npx -y agentic-awesome-skills --skills <candidate> --dry-run`
4. **Log State:** Update the Table in Section 1 to record the activation.
5. **Prune on Completion:** Once the code is written, linted, and tests pass, run:
   `rm -rf ~/.agents/skills/<id>`
   and update the ledger status back to `IDLE` (or remove the row).
