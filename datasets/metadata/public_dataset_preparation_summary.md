# Public dataset preparation summary

## Existing data

The current clone had no actual pre-existing PCAP/PCAPNG files in the scanned project paths. The historical `datasets/metadata/dataset_manifest.csv` records useful public demo intentions, but the referenced raw files are absent here. `_non_mainline_archive/` has archive metadata only in this clone, so it is legacy reference rather than immediately usable data.

## Newly researched datasets

- CIC-IDS2017: official CIC/UNB source page, PCAP plus labeled CICFlowMeter CSV; manual download required because the current official download endpoint is a form/server-error path in this environment.
- CSE-CIC-IDS2018: official CIC/UNB page plus AWS Open Data bucket; selected processed CSVs downloaded, raw daily PCAP archives intentionally not downloaded because they are tens of GB each.
- CTU-13: official Stratosphere/MCFP source; Scenario 1 botnet-only PCAP and bidirectional flow labels downloaded.
- UNSW-NB15: official UNSW page saved; raw PCAP is about 100GB and official files are behind SharePoint/browser download, so no data file was downloaded.

## Actual downloads

- `datasets/public/ctu13/raw/botnet-capture-20110810-neris.pcap`
- `datasets/public/ctu13/labels/capture20110810.binetflow`
- `datasets/public/ctu13/metadata/CTU-Malware-Capture-Botnet-42_README.md`
- `datasets/public/cse_cic_ids2018/labels/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv`
- `datasets/public/cse_cic_ids2018/labels/Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv`
- `datasets/public/cse_cic_ids2018/labels/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv`
- `datasets/public/cse_cic_ids2018/labels/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv`
- Official/source metadata pages under `datasets/public/*/metadata/`.

## Manual downloads still required

- CIC-IDS2017 flow CSVs and selected PCAP subsets from the official CIC download flow.
- UNSW-NB15 CSV, event list, and ground truth from the official SharePoint/browser source.
- Any CIC/CSE raw PCAP larger than the 10GB budget requires explicit user confirmation.

## Coverage

Current public data covers:

- `TA01_01`: CSE FTP/SSH brute force CSV.
- `TA01_02`: CSE SQL Injection/XSS web attack CSV, medium confidence.
- `TA11_02`: CTU-13 From-Botnet labels and botnet-only PCAP; CSE Bot CSV.
- `TN01_01`: CSE Benign rows and CTU From-Normal rows.

Current gaps:

- `TA43_01`: reliable downloaded port-scan sample is still missing.
- `TA43_02`: reliable vulnerability-scan sample is still missing.
- `TA03_01`: reliable implant-placement sample is missing.
- `TA11_01`: reliable access-backdoor sample is missing.

## Feasibility and SFT readiness

The current public data is enough for a partial Qwen3.5-27B + RAG feasibility test focused on brute force, web exploit, bot/C2 callback, and normal traffic. It is not yet balanced enough for official-code LoRA/SFT preparation because reconnaissance scan and backdoor boundary classes are missing or low confidence.

Next steps: manually obtain CIC-IDS2017 CSV/selected PCAP for port scan and CIC web/brute force coverage; obtain UNSW CSV/ground truth for reconnaissance/exploit/backdoor candidate review; consider another trusted public backdoor/webshell PCAP source only if licensing and labels are clear.

## Verdict

`PUBLIC_DATA_PARTIAL_NEEDS_MORE_DOWNLOAD`
