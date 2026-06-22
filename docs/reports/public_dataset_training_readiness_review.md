# Public dataset training-readiness review

Updated: 2026-06-22 after the data-completion round.

## Decision

The project now has a credible **small real-API readiness set**, not an eight-class strict benchmark. Public external-high PCAP records exist only for `TA43_01` and `TA11_02`; high flow-only records exist for `TA01_01` and `TN01_01`. `TA01_02` remains external-medium. `TA43_02`, `TA03_01`, and `TA11_01` are covered only by harmless `synthetic_controlled` fixtures.

SFT/LoRA remains deferred. Nothing in this round is promoted into a training set.

## Runnable record inventory

Counts are record instances with classification evidence, not catalog entries. PCAP and flow-only counts remain separate.

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
| **Total** | **6** | **9** | **7** | **0** | **25** |

`external_low=0` means no low-confidence candidate was normalized into a runnable evaluation record. Low catalog mappings still exist for infiltration/backdoor/botnet/reconnaissance labels and remain manual analysis only.

## New public data

The corrected Wireshark GitLab wiki attachment yielded three small official Nmap captures: default port scan, failed OS discovery, and successful OS discovery. The archive README gives exact commands; `capinfos`, TShark and Zeek all parsed them, and each produces one high-fanout `scan_group`. They are `external_high_pcap` for `TA43_01`, never `TA43_02`.

No small downloadable source with equally clear labels was found for the three main gaps. Two candidates were catalogued but not downloaded:

- Kaggle Attack Scenario PCAP collection: 218,964,654 bytes and CC0 on its data card, but labels are implicit filenames and download requires a manual credential/workflow review. Treat potential Hydra/normal cases as medium and generic backdoor cases as low.
- CyberDefenders WebStrike: the official walkthrough describes webshell upload and later reverse-shell activity, but account/terms, PCAP-only acquisition, and per-session phase/direction review remain manual.

No malware binary, challenge payload, recovered object, or file over 10 GB was downloaded or extracted.

## Synthetic-controlled boundary coverage

Twenty-four new loopback PCAPs (three per code) total 183,114 bytes. Together with the historical localhost port-scan fixture, the synthetic inventory has 25 records. All use fixed responses and inert marker strings; the server never saves uploads, executes commands, implements a shell/backdoor, contacts a non-loopback address, or uses malware.

Synthetic labels express intended behavior in a controlled fixture. They are useful for parser, prompt/RAG and missing-boundary tests only and are excluded from strict metrics and training claims.

## Strict evaluation readiness

The current public coverage file has 15 strict external rows: 6 PCAP/session-derived and 9 flow-only. This is still far below the preferred 20 high-confidence records per class and covers only four codes across the two domains.

- Strict PCAP: `TA43_01=3`, `TA11_02=3`.
- Strict flow-only: `TA01_01=5`, `TN01_01=4`.
- Coverage-only external-medium: `TA01_02=5`, `TA11_02=2`.

Do not report one blended eight-class accuracy. Report `external_high_pcap`, `external_high_flow`, `external_medium`, and `synthetic_controlled` separately. CTU-13 remains source-label ground truth rather than official competition truth; inspect behavior-level errors rather than assuming every infected-host session is visibly callback traffic.

## Missing external high PCAP

`TA43_02`, `TA01_01`, `TA01_02`, `TA03_01`, `TA11_01`, and `TN01_01` still lack external-high PCAP records. The most important semantic gaps remain:

- `TA43_02`: require explicit NSE/Nikto/OpenVAS/version/CVE/plugin probing, not ordinary fanout.
- `TA03_01`: require visible upload/deployment/persistence evidence, not exploit or callback alone.
- `TA11_01`: require attacker/operator access to an existing control endpoint and direction context, not victim callback or ordinary administration.

## Acquisition states

`download_manifest.csv` now has 47 rows: 20 `downloaded`, 13 `already_exists`, 9 `manual_required`, 5 `skipped_large`, and 0 `failed`. The old zero-byte Wireshark failure was repaired through the current official GitLab wiki attachment. Manual/skipped entries are catalog state, not usable instance counts.
