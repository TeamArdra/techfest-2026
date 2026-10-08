# P4 MAVLink-2 signing summary - live SITL trials (generated; do not edit)

Environment: **SITL**. Attack: the same informed expected-GCS-impersonation forgery as the P2 batch (sysid 255/190, correctly-tracked sequence), run once signing is bootstrapped and the IDS profile's `require_signing` is forced on. Five questions scored separately (see module docstring): legitimate-command acceptance, forged-command acceptance (command-path effect), IDS observation, detection via the new signing rule, detection via any rule. Regenerate: `scripts/sitl/make_p4_summary.py <manifests> --out <this file>`.

- Trials: **10**; passing the integrity gate (no hook errors, >=1 forged frame, legit ack confirmed signed): **10**.
- **Legitimate signed command accepted**: **10/10**.
- **Unsigned forged command REJECTED (0 acks)** -- command-path effect: **10/10**.
- **IDS observed the forged bytes** (verifying parser's `sig_invalid` rose by >= the number of forged frames): **10/10**.
- **Link-level detection via the new signing rule** (`sig_invalid_count` evidence) in the forged-frame window: **10/10**.
- **Any rule fired** in that window (includes the pre-existing, cruder `signed_ratio` rule -- see Limitations): **10/10**.
- Pre-onset false alarms, new signing rule only (clean baseline): **10/400** decisions.
- Pre-onset false alarms, ANY rule (includes the one-time bootstrap transient + the continuously-noisy `signed_ratio` rule -- see Limitations): **307/400** decisions.

| trial | idx | forged | legit ack ok | path rejected | sig observed | sig-rule detected | any detected | pre FA (sig-rule) | pre FA (any) | evidence (sample) |
|---|---|---|---|---|---|---|---|---|---|---|
| p4_sign_n10_trial_001 | 0 | 2 | yes | yes | yes | yes | yes | 1/40 | 30/40 | unsigned messages present (signed ratio 0.99); unsigned messages present (signed ratio 0.99) |
| p4_sign_n10_trial_002 | 1 | 2 | yes | yes | yes | yes | yes | 1/40 | 30/40 | unsigned messages present (signed ratio 0.99); unsigned messages present (signed ratio 0.99) |
| p4_sign_n10_trial_003 | 2 | 2 | yes | yes | yes | yes | yes | 1/40 | 31/40 | rogue telemetry source(s): sys253/comp192; unsigned messages present (signed ratio 0.99) |
| p4_sign_n10_trial_004 | 3 | 2 | yes | yes | yes | yes | yes | 1/40 | 31/40 | rogue telemetry source(s): sys253/comp192; unsigned messages present (signed ratio 0.99) |
| p4_sign_n10_trial_005 | 4 | 2 | yes | yes | yes | yes | yes | 1/40 | 30/40 | unsigned messages present (signed ratio 0.99); unsigned messages present (signed ratio 0.99) |
| p4_sign_n10_trial_006 | 5 | 2 | yes | yes | yes | yes | yes | 1/40 | 30/40 | unsigned messages present (signed ratio 0.99); unsigned messages present (signed ratio 0.99) |
| p4_sign_n10_trial_007 | 6 | 2 | yes | yes | yes | yes | yes | 1/40 | 30/40 | unsigned messages present (signed ratio 0.99); unsigned messages present (signed ratio 0.99) |
| p4_sign_n10_trial_008 | 7 | 2 | yes | yes | yes | yes | yes | 1/40 | 31/40 | rogue telemetry source(s): sys253/comp192; unsigned messages present (signed ratio 0.99) |
| p4_sign_n10_trial_009 | 8 | 2 | yes | yes | yes | yes | yes | 1/40 | 34/40 | unsigned messages present (signed ratio 0.98); unsigned messages present (signed ratio 0.98) |
| p4_sign_n10_trial_010 | 9 | 2 | yes | yes | yes | yes | yes | 1/40 | 30/40 | unsigned messages present (signed ratio 0.99); unsigned messages present (signed ratio 0.99) |

## Provenance
- PX4: ['v1.18.0-rc1-27-gc239c63807']; detector profile ['configs/px4_sitl'], model ['px4']; aegisflight commit ['feaba05']; dirty-path counts [7, 8, 9, 11] (uncommitted changes at run time; not a clean-commit reproduction until committed).

## Limitations
- n=10 is the design floor, reported as counts (no confidence interval); one airframe/world/host; fresh SITL boot AND a cleared signing-key file per trial (`run_trial_batch.sh`); unsigned-until-bootstrapped link; vehicle disarmed on the ground; SITL only.
- **The one-time signing-bootstrap transient**: characterized separately, SITL-free in spirit but confirmed live across 6 independent diagnostic runs before this batch -- ~1s of spurious `sig_invalid` right after `enable_signing()` as PX4's own downlink and the verifier's per-stream timestamp tracking settle, then exactly 0 for the remainder of a clean trial. This is NOT an ongoing noise floor; it is bucketed into the trial's PRE-onset window (onset is several seconds later), so it shows up as pre-onset false alarms, not as attack detections -- reported, not hidden.
- **The pre-existing `signed_ratio` rule is link-wide and blunt**: it fires on ANY unsigned traffic regardless of source, and this harness deliberately has one always-unsigned inert carrier client (the attack's own piggyback-delivery mechanism, not a calibrated real deployment) -- so 'any rule fired' / 'any FA' numbers above are expected to look noisy and must not be read as a false-alarm rate for a real deployment. The NEW `sig_invalid_count` rule is the clean, intended signal and is reported separately for exactly this reason.
- Detection here is **link-level** (IDS-side), separate from and in addition to PX4's own command-path rejection -- the two are never merged into one number.
- A single command (force-disarm) against an already-disarmed vehicle; not evidence about a different command or one with in-flight consequence.
- The informed attacker's identity-impersonation mechanics are unchanged from the P2 batch; this experiment is only about what happens once signing is active, not a new attack design.
