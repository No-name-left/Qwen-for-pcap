# Public dataset training-readiness review

Date: 2026-06-22

## Executive decision

The local public assets are sufficient for pipeline smoke tests, targeted RAG/prompt boundary debugging, and a narrow `TA11_02` format-following experiment. They are **not sufficient for a strict official-code test set** and **not sufficient for balanced eight-class SFT/LoRA**. No medium/low-confidence label is promoted to high confidence, and flow-only records remain a separate domain.

The current evaluation split has 20 records: 1 high PCAP-derived `TA43_01` scan_group, 3 high PCAP/session-derived `TA11_02` sessions, 5 high flow-only `TA01_01`, 4 high flow-only `TN01_01`, 5 medium flow-only `TA01_02`, and 2 medium flow-only `TA11_02`. Three official classes have zero runnable records.

## Assets actually present

### PCAP

| Source | Files | Size | Label use |
|---|---:|---:|---|
| Controlled Nmap | `generated_nmap_local_scan.pcap` | 95,168 B | high controlled `TA43_01`; engineering fixture, not broad public-test coverage |
| CTU-13 Neris scenario 42 | `botnet-capture-20110810-neris.pcap` | 58,266,506 B | high `TA11_02` only after matching scenario/flow labels |
| CTU-13 Neris scenario 43 | `botnet-capture-20110811-neris.pcap` | 36,261,479 B | same |
| CTU-13 fast-flux scenario 46 | `botnet-capture-20110815-fast-flux.pcap` | 30,941,919 B | same; do not infer implant/access phase |
| CTU-13 Donbot scenario 47 | `botnet-capture-20110816-donbot.pcap` | 5,284,095 B | same |

### Flow assets

- Four CSE-CIC-IDS2018 CICFlowMeter CSVs total about 1.20 GB: Wednesday 14 February (FTP/SSH brute force), Thursday 22 February (Web attacks), Thursday 1 March (infiltration), and Friday 2 March (Bot). These are **flow-only** and cannot be presented as Zeek/PCAP sessions.
- Four CTU-13 binetflow files total about 1.00 GB accompany the four available PCAPs. They are alignment/label companions for those captures, not an independent PCAP-derived feature representation.

Metadata HTML/README files are provenance evidence, not traffic samples. The zero-byte Wireshark `NMap-Captures.zip` is failed and unused.

## Not acquired

Manifest status totals are 15 `downloaded`, 13 `already_exists`, 7 `manual_required`, 5 `skipped_large`, and 1 `failed`.

- `manual_required`: BoT-IoT 5% CSV/Argus; CICIoT2023 small labeled subset; analyst-selected Malware-Traffic-Analysis PCAP; ToN-IoT processed flows; UNSW-NB15 CSV/features/ground truth. Malware sample ZIP/executables from Malware-Traffic-Analysis and Stratosphere MCF are also manual entries but explicitly forbidden: never download, extract, or execute them.
- `skipped_large`: BoT-IoT 69 GB PCAP, CIC-IDS2017 full PCAP bundle, CSE-CIC-IDS2018 full AWS corpus, full IoT-23 PCAP, and roughly 100 GB UNSW-NB15 PCAP set.
- `failed`: the historical Wireshark NMap ZIP is zero bytes.

No new traffic package was downloaded during this review because the existing manifest was enough to establish readiness and no already-reviewed small high-value URL closed a missing class safely.

## Technique-by-technique sources and permitted use

| Code | Available local evidence | Confidence / domain | Strict test | Prompt/RAG boundary | SFT/LoRA |
|---|---|---|---|---|---|
| `TA43_01` | controlled Nmap `scan_group` | high controlled; PCAP/session-derived | smoke only (n=1) | yes | no class training; one format example at most |
| `TA43_02` | none; BoT-IoT Service Scan/UNSW Analysis/CSE enumeration only catalogued | medium/low candidate; mainly flow | no | yes, as unlabeled boundary scenarios | no |
| `TA01_01` | CSE FTP/SSH brute-force rows | high source label; flow-only | separate flow smoke (n=5), not strict threshold | yes | cautiously for flow-format/boundary training after split/review; below 50 |
| `TA01_02` | CSE SQL Injection/XSS rows | medium; flow-only, payload absent | no | yes | no strong supervision |
| `TA03_01` | none; infiltration/backdoor-family candidates | low/manual | no | conceptual boundary only | never from current candidates |
| `TA11_01` | none; infiltration/backdoor-family candidates | low/manual | no | conceptual boundary only | never from current candidates |
| `TA11_02` | CTU-13 PCAP+labels; CSE Bot flow rows | CTU high PCAP/session; CSE medium flow | PCAP smoke (n=3), below 20 | yes | 57 separately reviewed CTU `accept_high` candidates can cautiously teach schema/behavior, but one-class/source bias remains |
| `TN01_01` | CSE Benign; CTU explicit normal candidates | high flow-only in current eval; CTU background excluded | separate flow smoke (n=4), below 20 | yes | reviewed explicit normal only; current count below 50 and domain balance inadequate |

“High” above means close semantic alignment to a public source label; it is not official competition truth. Medium/low rows must not enter the high-confidence metric or strong-supervision split.

## Strict-test readiness

No class reaches 20 high-confidence records in the current holdout. The high PCAP/session-derived subset covers only two codes and has four records total. The high flow-only subset covers two different codes and has nine records total. Therefore an overall eight-class accuracy or macro-F1 would be misleading. Current valid reporting units are:

1. PCAP/session-derived smoke metrics by class and source.
2. Flow-only boundary metrics reported separately.
3. Medium-confidence exploratory errors, never merged into high-confidence results.

## SFT/LoRA readiness

The reviewed candidate inventory contains 181 rows, but only 57 are `accept_high`, all `TA11_02`. Another 94 are `accept_medium_needs_review`; 30 are rejected, holdout, duplicate/leakage, or ambiguous background. This fails the recommended minimum of 50 quality examples **per class**, as well as source/domain balance.

Permitted cautious experiment: use reviewed, provenance-tagged examples to stabilize exact JSON, legal-code closure, input field handling, and a few discrimination rules. Keep `record_type`/source domain explicit; reserve PCAP/source groups before splitting; avoid duplicating the public evaluation holdout. Do not claim that such tuning teaches general network-security knowledge.

Never use broad `Infiltration`, `Backdoors`, `Bot`, `Mirai`, `Background`, generic malware, service enumeration, or narrative-only labels as strong technique supervision without phase-, direction-, and record-level verification. Never use recovered malicious binaries.

## Priority gaps

### `TA43_02` vulnerability scan — still missing

Acquire small controlled or explicitly documented PCAPs from Nikto, OpenVAS/Nessus, Nmap NSE vulnerability scripts, service/banner enumeration, and Web vulnerability scanners. Preserve scanner command, target scope, time window, and negative plain-Nmap scans. Promote to high only when vulnerability-specific probes—not merely many ports—are packet/session visible.

### `TA03_01` backdoor implantation — still missing

Build or curate safe network-only scenarios for webshell upload, payload download followed by deployment, backdoor placement, and post-exploit persistence. A download or exploit alone does not prove installation. Require timeline/packet evidence; do not acquire or execute malware.

### `TA11_01` backdoor access — still missing

Curate attacker-initiated connections to an existing backdoor, verified Webshell access, interactive reverse-shell/operator sessions, and post-backdoor control. Preserve endpoint roles and distinguish an inbound/operator access session from the victim-initiated callback that belongs to `TA11_02`.

## Next data action

First generate several small, safe, controlled scanner PCAPs (plain Nmap negatives plus Nmap NSE/Nikto positives), because this can close the `TA43_01`/`TA43_02` boundary without malware. For `TA03_01`/`TA11_01`, prefer benign lab services and scripted dummy payload text with explicit timelines; capture network traffic only. Keep every acquisition under the manifest policy and below the 10 GB per-file ceiling.
