# Data completion round report

Date: 2026-06-22

## Outcome

This round improves small-evaluation readiness without claiming eight-class public coverage. Three official Wireshark Nmap PCAPs were added as `external_high_pcap` for `TA43_01`. The missing classes `TA43_02`, `TA03_01`, and `TA11_01` remain without external-high data and receive only clearly marked localhost synthetic fixtures.

## Tier totals

| Technique | external_high_pcap | external_high_flow | external_medium | external_low | synthetic_controlled |
|---|---:|---:|---:|---:|---:|
| `TA43_01` | 3 | 0 | 0 | 0 | 4 |
| `TA43_02` | 0 | 0 | 0 | 0 | 3 |
| `TA01_01` | 0 | 5 | 0 | 0 | 3 |
| `TA01_02` | 0 | 0 | 5 | 0 | 3 |
| `TA03_01` | 0 | 0 | 0 | 0 | 3 |
| `TA11_01` | 0 | 0 | 0 | 0 | 3 |
| `TA11_02` | 3 | 0 | 2 | 0 | 3 |
| `TN01_01` | 0 | 4 | 0 | 0 | 3 |

Counts come from the tiered public coverage records and synthetic manifest. Manual/skipped candidates are not instances.

## Public search and acquisition

### Downloaded

Wireshark SampleCaptures' current GitLab wiki archive URL repaired the historical zero-byte Nmap ZIP. The 114,641-byte archive contains captures and a README only. Three selected captures were extracted:

- `nmap_standard_scan.pcap`: 152,292 bytes; README command `nmap 192.168.100.102`.
- `nmap_OS_scan.pcap`: 161,520 bytes; README command `nmap -O -Pn 192.168.100.102`.
- `nmap_OS_scan_successful.pcap`: 157,862 bytes; README command `nmap -O -Pn 192.168.100.101`.

All three are parseable PCAP, produce one Zeek scan_group each, and remain `TA43_01`; OS/version discovery is not automatically vulnerability scanning.

### Catalogued/manual only

- Kaggle Attack Scenario Dataset: public data card reports 218,964,654 bytes and CC0, with Hydra, normal, exploit, bot/malware and backdoor-named PCAPs. It was not downloaded because labels are filenames only and the download workflow/credentials require review. Hydra/normal would begin at medium; `distcc_exec_backdoor` is low for `TA11_01` until phase/direction evidence is established.
- CyberDefenders WebStrike: official walkthrough describes a webshell upload and later reverse-shell communications. It was not downloaded because account/terms and PCAP-only selection need manual review. If acquired, upload and access sessions must be separated before any label promotion.

No public high-confidence source was found for `TA43_02`, `TA03_01`, or `TA11_01` that was simultaneously small, directly downloadable, safely PCAP-only, and phase-specific.

## Synthetic completion

The safe generator created 24 fresh PCAPs, three per official code, on `127.0.0.1` only. Total size is 183,114 bytes. Scenarios cover TCP fanout, scanner-like paths, repeated login failures, inert traversal/injection strings, discarded marker upload, fixed mock-control access, fixed heartbeat callback, and normal HTTP.

Safety invariants are enforced in code: no host argument, no public target, no command execution, no upload persistence, no functional shell/backdoor, no real malware and no binary extraction. `synthetic_controlled_manifest.csv` retains intended label, generator, hash, safety notes and limitations. The historical controlled scan remains a fourth `TA43_01` synthetic fixture.

## Real API candidates

`real_api_candidate_records.jsonl` has 24 rows, exactly three per technique. The strict subset has 12 external-high rows (`TA43_01`, `TA01_01`, `TA11_02`, `TN01_01`). The coverage subset has all 24 and adds external-medium `TA01_02` plus synthetic `TA43_02`, `TA03_01`, and `TA11_01`.

Model-visible `record_id` and `pcap_id` values are opaque stable aliases. Semantic source IDs/paths remain audit fields outside `classification_record`, preventing dataset names such as `bruteforce`, `webattack`, `nmap`, or synthetic codes from leaking the expected class into prompts.

This split is designed to reveal pipeline and boundary failures. It is not an eight-class strict accuracy claim and is not a training set.
