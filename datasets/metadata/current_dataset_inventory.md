# Current dataset inventory

## Summary

- Actual PCAP/PCAPNG files found now: 1.
- Actual CSV/label/answer/metadata-like files found in scoped directories: 18.
- Pre-existing raw public PCAP files before this task: none found in this clone.
- `_non_mainline_archive/` currently contains archive manifests, but no raw PCAP files were found by the scan.
- `datasets/metadata/dataset_manifest.csv` contains historical rows for public demo datasets, but the referenced raw paths are absent in this clone.

## Current PCAP files

- `datasets/public/ctu13/raw/botnet-capture-20110810-neris.pcap` (58266506 bytes)

## Label and metadata status

- CTU-13 Scenario 1: downloaded botnet-only PCAP plus bidirectional flow labels; suitable for TA11_02/TN01_01 feasibility tests.
- CSE-CIC-IDS2018: downloaded selected processed flow CSVs; suitable for flow-level feasibility samples for TA01_01, TA01_02, TA11_02, TN01_01, with infiltration marked low-confidence/manual review.
- CIC-IDS2017: official source page saved as metadata; actual data download requires manual form/direct source recovery.
- UNSW-NB15: official source page saved as metadata; official files are behind SharePoint/browser download, and raw PCAP is about 100GB.

Full structured inventory is in `current_dataset_inventory.json`.
