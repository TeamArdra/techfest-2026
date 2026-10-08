# P2 expected-GCS impersonation summary - live SITL trials (generated; do not edit)

Environment: **SITL**. Attack: a fresh forged `COMMAND_LONG` (force-disarm) stamped with an EXPECTED GCS identity (sysid 255/compid 190), not a replay. Command-path effect, harness delivery and detection are scored separately (see the script docstring). Vehicle disarmed: an ACCEPTED ack is acceptance only, not an observable state change. Regenerate: `scripts/sitl/make_p2g_summary.py --variant LABEL=GLOB ... --out <this file>`.

## Variant: informed (tracks real seq)

- Trials: **10**; passing the integrity gate (no hook errors, >=1 injection): **10**; forged frames injected: **33**.
- **Command-path effect (SITL)**: trials where PX4 acked the forged command `MAV_RESULT_ACCEPTED`: **10/10**.
- **Harness delivery**: trials where every forged frame reached the IDS pipeline input: **10/10** (33/33 frames).
- **Seq continuity achieved** (attack-implementation check, not detection): **33/33** forged frames carried exactly (previous real 255/190 seq + 1).
- **Link-level detection (SITL)** within the forged-frame window (+5s): any threat decision **0/10**; identity/provenance rule **0/10**; sequence-continuity rule **0/10**.
- Pre-injection false alarms (pooled): **1/2139** decisions.

| trial | idx | injected | acks | first ack | delivered | seq-continuous | any | identity | seq-gap | pre FA | evidence (sample) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| p2g_inf_trial_001 | 0 | 2 | 2 | MAV_RESULT_ACCEPTED | yes | 2/2 | NO | NO | NO | 0/273 | - |
| p2g_inf_trial_002 | 1 | 5 | 5 | MAV_RESULT_ACCEPTED | yes | 5/5 | NO | NO | NO | 0/233 | - |
| p2g_inf_trial_003 | 2 | 2 | 2 | MAV_RESULT_ACCEPTED | yes | 2/2 | NO | NO | NO | 0/213 | - |
| p2g_inf_trial_004 | 3 | 3 | 3 | MAV_RESULT_ACCEPTED | yes | 3/3 | NO | NO | NO | 0/258 | - |
| p2g_inf_trial_005 | 4 | 3 | 3 | MAV_RESULT_ACCEPTED | yes | 3/3 | NO | NO | NO | 1/111 | - |
| p2g_inf_trial_006 | 5 | 5 | 5 | MAV_RESULT_ACCEPTED | yes | 5/5 | NO | NO | NO | 0/299 | - |
| p2g_inf_trial_007 | 6 | 3 | 3 | MAV_RESULT_ACCEPTED | yes | 3/3 | NO | NO | NO | 0/116 | - |
| p2g_inf_trial_008 | 7 | 4 | 4 | MAV_RESULT_ACCEPTED | yes | 4/4 | NO | NO | NO | 0/172 | - |
| p2g_inf_trial_009 | 8 | 3 | 3 | MAV_RESULT_ACCEPTED | yes | 3/3 | NO | NO | NO | 0/242 | - |
| p2g_inf_trial_010 | 9 | 3 | 3 | MAV_RESULT_ACCEPTED | yes | 3/3 | NO | NO | NO | 0/222 | - |

## Variant: naive (own counter)

- Trials: **10**; passing the integrity gate (no hook errors, >=1 injection): **10**; forged frames injected: **33**.
- **Command-path effect (SITL)**: trials where PX4 acked the forged command `MAV_RESULT_ACCEPTED`: **10/10**.
- **Harness delivery**: trials where every forged frame reached the IDS pipeline input: **10/10** (33/33 frames).
- **Seq continuity achieved** (attack-implementation check, not detection): **0/33** forged frames carried exactly (previous real 255/190 seq + 1).
- **Link-level detection (SITL)** within the forged-frame window (+5s): any threat decision **10/10**; identity/provenance rule **0/10**; sequence-continuity rule **10/10**.
- Pre-injection false alarms (pooled): **1/2133** decisions.

| trial | idx | injected | acks | first ack | delivered | seq-continuous | any | identity | seq-gap | pre FA | evidence (sample) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| p2g_naive_trial_001 | 0 | 2 | 2 | MAV_RESULT_ACCEPTED | yes | 0/2 | yes | NO | yes | 1/273 | sequence gap 201 > 30; ML anomaly score 0.80 ≥ 0.62 (driver: loss_ratio, z=+36.3) |
| p2g_naive_trial_002 | 1 | 5 | 5 | MAV_RESULT_ACCEPTED | yes | 0/5 | yes | NO | yes | 0/232 | sequence gap 209 > 30; ML anomaly score 0.81 ≥ 0.62 (driver: loss_ratio, z=+36.3) |
| p2g_naive_trial_003 | 2 | 2 | 2 | MAV_RESULT_ACCEPTED | yes | 0/2 | yes | NO | yes | 0/212 | sequence gap 214 > 30; ML anomaly score 0.82 ≥ 0.62 (driver: loss_ratio, z=+36.3) |
| p2g_naive_trial_004 | 3 | 3 | 3 | MAV_RESULT_ACCEPTED | yes | 0/3 | yes | NO | yes | 0/258 | sequence gap 204 > 30; ML anomaly score 0.80 ≥ 0.62 (driver: loss_ratio, z=+36.3) |
| p2g_naive_trial_005 | 4 | 3 | 3 | MAV_RESULT_ACCEPTED | yes | 0/3 | yes | NO | yes | 0/111 | sequence gap 234 > 30; ML anomaly score 0.84 ≥ 0.62 (driver: loss_ratio, z=+36.3) |
| p2g_naive_trial_006 | 5 | 5 | 5 | MAV_RESULT_ACCEPTED | yes | 0/5 | yes | NO | yes | 0/298 | sequence gap 197 > 30; ML anomaly score 0.79 ≥ 0.62 (driver: loss_ratio, z=+36.3) |
| p2g_naive_trial_007 | 6 | 3 | 3 | MAV_RESULT_ACCEPTED | yes | 0/3 | yes | NO | yes | 0/116 | sequence gap 233 > 30; ML anomaly score 0.84 ≥ 0.62 (driver: loss_ratio, z=+36.3) |
| p2g_naive_trial_008 | 7 | 4 | 4 | MAV_RESULT_ACCEPTED | yes | 0/4 | yes | NO | yes | 0/167 | sequence gap 223 > 30; ML anomaly score 0.83 ≥ 0.62 (driver: loss_ratio, z=+36.3) |
| p2g_naive_trial_009 | 8 | 3 | 3 | MAV_RESULT_ACCEPTED | yes | 0/3 | yes | NO | yes | 0/243 | sequence gap 208 > 30; ML anomaly score 0.81 ≥ 0.62 (driver: loss_ratio, z=+36.3) |
| p2g_naive_trial_010 | 9 | 3 | 3 | MAV_RESULT_ACCEPTED | yes | 0/3 | yes | NO | yes | 0/223 | sequence gap 212 > 30; ML anomaly score 0.81 ≥ 0.62 (driver: loss_ratio, z=+36.3) |

## Provenance
- PX4: ['v1.18.0-rc1-27-gc239c63807']; detector profile ['configs/px4_sitl'], model ['px4']; aegisflight commit ['f1608bc']; dirty-path counts [2, 3] (uncommitted changes at run time; not a clean-commit reproduction until committed).

## Limitations
- n=10 per variant is the design floor, reported as counts (no confidence interval); one airframe/world/host; fresh SITL boot per trial; unsigned link; vehicle disarmed on the ground; SITL only.
- The informed attacker reads the 255/190 heartbeat sequence off the clear-text link; that is a statement about an attacker with read access to the link (the MITM position this proxy already assumes), not about a remote one.
- Link-level only: this says what the IDS could see on its tap; it says nothing about vehicle behaviour, and an ACCEPTED ack of a disarm sent to an already-disarmed vehicle is not a demonstrated physical effect.
- Only the rules present in the PX4-profile detector were exercised; a deliberately designed duplicate-sequence or timing-consistency check (not implemented) is not evaluated here.
