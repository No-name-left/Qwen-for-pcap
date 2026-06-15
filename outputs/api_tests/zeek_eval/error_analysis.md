# Zeek eval error analysis

- Audited records: 7
- Includes all completed errors and portscan-related completed sample.

## cse_cic_ids2018_bruteforce_wed14::flow::000011
- expected/predicted: TA01_01 / TN01_01
- confidence: 0.85
- parser_source: flow_csv
- label_quality: high_flow_only
- suspected_failure_reason: label_mapping_uncertain
- model reason: Single flow with no authentication failure signatures or repeated attempts constitutes weak evidence.

## cse_cic_ids2018_bruteforce_wed14::flow::000012
- expected/predicted: TA01_01 / TN01_01
- confidence: 0.95
- parser_source: flow_csv
- label_quality: high_flow_only
- suspected_failure_reason: label_mapping_uncertain
- model reason: Single connection record lacks repeated authentication attempts or IDS signatures required for brute force classification.

## cse_cic_ids2018_webattack_thu22::flow::000011
- expected/predicted: TA01_02 / TN01_01
- confidence: 0.9
- parser_source: flow_csv
- label_quality: medium_flow_only
- suspected_failure_reason: label_mapping_uncertain
- model reason: Minimal packet count and lack of alert or payload evidence classify as normal per weak evidence policy.

## cse_cic_ids2018_webattack_thu22::flow::000012
- expected/predicted: TA01_02 / TN01_01
- confidence: 0.9
- parser_source: flow_csv
- label_quality: medium_flow_only
- suspected_failure_reason: label_mapping_uncertain
- model reason: Zero bytes and no alerts indicate weak evidence requiring fallback to normal traffic classification.

## ctu13_scenario1::session::000001
- expected/predicted: TA11_02 / TN01_01
- confidence: 0.85
- parser_source: zeek_conn
- label_quality: high
- suspected_failure_reason: model_misclassification
- model reason: Session shows standard Google Update HTTP traffic with no suricata alerts or exploit payloads.

## ctu13_scenario1::session::000003
- expected/predicted: TA11_02 / TN01_01
- confidence: 0.85
- parser_source: zeek_conn
- label_quality: high
- suspected_failure_reason: model_misclassification
- model reason: Session shows standard DNS resolution without scan patterns or exploit indicators.

## feasibility_portscan::scan_group::000001
- expected/predicted: TA43_01 / TA43_01
- confidence: 0.95
- parser_source: zeek_conn
- label_quality: high_controlled
- suspected_failure_reason: none
- model reason: Multi-port TCP scanning with 181 unique destination ports and 98.9% failed connection rate indicates reconnaissance port scan.
