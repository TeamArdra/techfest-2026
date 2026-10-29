## Time to first alert (detected sessions only)

`p95_s` is blank when fewer than 20 detected sessions exist. Undetected sessions are excluded here and listed in the CI table.

| name | detected_sessions | min_s | median_s | p95_s | max_s |
|---|---|---|---|---|---|
| combo | 12 | 0.0 | 0.0 |  | 1.4 |
| command_injection | 12 | 0.0 | 0.2 |  | 0.4 |
| dos | 16 | 0.0 | 0.0 |  | 0.8 |
| firmware_integrity | 4 | 0.2 | 0.5 |  | 0.8 |
| gps_spoofing | 12 | 0.0 | 0.5 |  | 1.2 |
| mavlink_anomaly | 16 | 0.0 | 0.0 |  | 0.4 |
| telemetry_manipulation | 16 | 0.0 | 0.1 |  | 18.8 |
| command_injection:arm_disarm_burst | 4 | 0.0 | 0.3 |  | 0.4 |
| command_injection:mode_flip | 4 | 0.0 | 0.1 |  | 0.2 |
| command_injection:rogue_command | 4 | 0.2 | 0.2 |  | 0.4 |
| dos+telemetry_manipulation | 3 | 0.0 | 0.0 |  | 0.0 |
| dos:blackout | 4 | 0.0 | 0.1 |  | 0.2 |
| dos:flood | 4 | 0.0 | 0.0 |  | 0.0 |
| dos:gnss_jamming | 4 | 0.8 | 0.8 |  | 0.8 |
| dos:latency | 4 | 0.0 | 0.0 |  | 0.0 |
| firmware_integrity:default | 4 | 0.2 | 0.5 |  | 0.8 |
| gps_spoofing+command_injection | 3 | 0.8 | 1.0 |  | 1.4 |
| gps_spoofing+mavlink_anomaly | 3 | 0.0 | 0.0 |  | 0.0 |
| gps_spoofing:gradual_drift | 4 | 1.0 | 1.1 |  | 1.2 |
| gps_spoofing:replay_freeze | 4 | 0.4 | 0.5 |  | 0.8 |
| gps_spoofing:sudden_offset | 4 | 0.0 | 0.0 |  | 0.0 |
| mavlink_anomaly:packet_loss | 4 | 0.0 | 0.3 |  | 0.4 |
| mavlink_anomaly:rate_spike | 4 | 0.0 | 0.0 |  | 0.0 |
| mavlink_anomaly:rogue_sysid | 4 | 0.0 | 0.0 |  | 0.0 |
| mavlink_anomaly:seq_scramble | 4 | 0.0 | 0.0 |  | 0.0 |
| telemetry_manipulation+firmware_integrity | 3 | 0.0 | 0.0 |  | 0.0 |
| telemetry_manipulation:altitude_bias | 4 | 0.0 | 0.0 |  | 0.0 |
| telemetry_manipulation:battery_jump | 4 | 0.2 | 0.3 |  | 0.4 |
| telemetry_manipulation:frozen_attitude | 4 | 0.4 | 4.5 |  | 18.8 |
| telemetry_manipulation:speed_mismatch | 4 | 0.0 | 0.0 |  | 0.0 |
