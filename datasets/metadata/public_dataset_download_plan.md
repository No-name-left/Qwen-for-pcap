# Public dataset download plan

## CIC-IDS2017

- Source: https://www.unb.ca/cic/datasets/ids-2017.html
- Data types: pcap, flow_csv, labels, metadata
- Expected size: PCAP day files listed as 7.8GB-13GB each; full week roughly >50GB; MachineLearningCSV/GeneratedLabelledFlows available through official download form but size not confirmed here.
- Label granularity: flow/session-like CICFlowMeter rows plus day/time attack schedule
- Covered official codes: TA43_01, TA01_01, TA01_02, TA11_02, TN01_01
- Mapping confidence: medium
- Download priority: high
- Should download now: false
- Reason: Official page is available but download endpoint requires a form and current direct access returned a server error/502 from this environment. Do not bypass; mark manual_download_required.

## CSE-CIC-IDS2018

- Source: https://www.unb.ca/cic/datasets/ids-2018.html ; https://registry.opendata.aws/cse-cic-ids2018/
- Data types: flow_csv, pcap, logs, metadata
- Expected size: Selected processed CSVs are 108MB-383MB each; raw daily PCAP archives in S3 are about 38GB-59GB each and were not downloaded.
- Label granularity: flow/session-like CICFlowMeter rows, per-day attack schedules
- Covered official codes: TA01_01, TA01_02, TA11_02, TN01_01, TA03_01?, TA11_01?
- Mapping confidence: medium
- Download priority: high
- Should download now: true
- Reason: Public AWS Open Data bucket requires no credentials for processed CSV files; selected CSVs stay far below 10GB and cover brute force, web attack, bot, infiltration, and benign.

## CTU-13

- Source: https://www.stratosphereips.org/datasets-ctu13
- Data types: pcap, netflow, labels, metadata
- Expected size: Scenario 1 botnet-only PCAP 56MB; bidirectional binetflow 369MB; full CTU-13 tar 1.9GB; complete private PCAP is not public.
- Label granularity: bidirectional NetFlow labels plus botnet-only PCAP scenario
- Covered official codes: TA11_02, TN01_01
- Mapping confidence: high
- Download priority: high
- Should download now: true
- Reason: Authoritative Stratosphere/MCFP source, public botnet-only PCAP and labeled bidirectional flows are small enough and directly relevant to C2/callback feasibility.

## UNSW-NB15

- Source: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- Data types: pcap, bro, argus, flow_csv, ground_truth, metadata
- Expected size: Raw PCAP approximately 100GB; four CSV files contain 2,540,044 records; train/test partitions contain 175,341 and 82,332 records.
- Label granularity: flow records plus ground truth/event list; PCAP/log files also exist through SharePoint
- Covered official codes: TA43_01?, TA43_02?, TA01_02, TA03_01?, TA11_01?, TN01_01
- Mapping confidence: medium
- Download priority: medium
- Should download now: false
- Reason: Official data is behind SharePoint/browser link from the source page. Do not use unofficial mirrors by default; raw PCAP is too large for this task.

