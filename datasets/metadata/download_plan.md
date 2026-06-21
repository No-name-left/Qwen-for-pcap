# Public dataset download plan

Updated: 2026-06-22

## Guardrails

- Default profile is `coverage`; a single artifact over 10GB is never downloaded unless both `--allow-large` and an adequate `--max-gb` are supplied.
- Existing non-empty files are hashed and retained. Downloads use `.part` plus HTTP Range when supported, then atomic rename.
- Only traffic captures, flow/Zeek labels, README files and source metadata are in the allowlist.
- Malware executables and password-protected sample archives are excluded and recorded as `skipped_malware_binary` in notes/reason where applicable.
- Login, SharePoint, Kaggle and CAPTCHA-gated sources are `manual_required`; no credentials are stored.

## Profiles

| Profile | Automated scope | Intentionally excluded |
|---|---|---|
| `minimal` | Official source pages plus inventory of existing local assets | All new PCAP/flow downloads |
| `coverage` | Minimal plus three small CTU-13 botnet-only PCAPs and their labeled binetflow files | Full CIC/UNSW/IoT/BoT-IoT corpora |
| `pcap-heavy` | Coverage plus future explicitly allowlisted PCAP artifacts | Anything over the configured budget; all malware binaries |

## Priority actions

1. Keep CTU-13 Scenario 1 and existing CSE-CIC-IDS2018 CSVs; verify hashes instead of downloading again.
2. Add CTU MCFP scenarios 43, 46 and 47. They provide small botnet-only PCAPs with corresponding flow labels.
3. Obtain UNSW-NB15 training/testing CSV, feature list, event list and ground truth manually; keep full PCAP optional.
4. Obtain CIC-IDS2017 labeled flows or a source-approved small bundle; do not bulk-download PCAP by default.
5. Select individual CSE-CIC-IDS2018 processed objects; never run an unbounded `aws s3 sync`.
6. Prefer IoT-23 labeled-flow/small archives, BoT-IoT 5% CSV/Argus, and processed ToN-IoT variants.
7. Keep Malware-Traffic-Analysis.net PCAP selection manual and answer-key reviewed. Do not download sample ZIPs.

## Commands

```bash
python3 scripts/download_public_datasets.py --dry-run --profile coverage
python3 scripts/download_public_datasets.py --profile coverage --max-gb 1
python3 scripts/download_public_datasets.py --dry-run --dataset-id unsw_nb15
python3 scripts/download_public_datasets.py --profile pcap-heavy --allow-large --max-gb 10
```

Every run rewrites `datasets/metadata/download_manifest.csv` from the current filesystem plus the run result, so missing historical paths are not reported as downloaded.
