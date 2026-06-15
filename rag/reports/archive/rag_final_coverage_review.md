# RAG final coverage review

- Document total: 71

## Category statistics

- attack_types: 12
- attack_stages: 6
- tool_fields: 10
- protocols: 9
- signatures: 20
- false_positive_rules: 9
- aggregation_policy: 5

## Attack type coverage

- normal: covered
- port_scan: covered
- exploit: covered
- backdoor: covered
- trojan_callback: covered
- c2: covered
- other_attack: covered

## Attack stage coverage

- none: covered
- reconnaissance: covered
- initial_access: covered
- persistence: covered
- command_and_control: covered

## Tool field coverage

- tshark: covered
- zeek: covered
- conn.log: covered
- dns: covered
- http: covered
- tls: covered
- weird: covered
- notice: covered
- files.log: covered
- suricata: covered
- signature: covered
- category: covered
- severity: covered

## Key signature coverage

- strrat: covered
- ms17-010: covered
- doublepulsar: covered
- invalid checksum: covered
- sql injection: covered
- xss: covered
- command injection: covered
- dns tunnel: covered
- brute force: covered
- ddos: covered
- scan: covered

## False-positive boundary coverage

- low-signal: covered
- protocol anomaly: covered
- port 445 alone: covered
- periodic: covered
- dns tunnel: covered
- web exploit: covered
- high volume: covered

## Source sufficiency

- STRRAT: official/public/local_rule
- MS17-010: official/public/local_rule
- DOUBLEPULSAR: public/local_rule
- protocol anomaly: official_suricata/local_rule
- Zeek fields: official
- Suricata fields: official/local_rule
- false-positive policy: distilled/project_analysis
- aggregation policy: distilled/project_analysis

## Topics still mostly distilled

- false-positive policy: optional manual source enrichment recommended.
- aggregation policy: optional manual source enrichment recommended.

## Retrieval test preparation

- Ready for retrieval test: yes
- All retrieval query expected_doc_ids exist and required topics are covered.

## Verdict

- clear verdict: ready
- Required fixes before chunk/index/query stage: none.
- Optional enhancements: pin Zeek/Suricata docs to deployed runtime versions; add more public references for false-positive policy and aggregation policy; convert local rule metadata into structured JSONL.
