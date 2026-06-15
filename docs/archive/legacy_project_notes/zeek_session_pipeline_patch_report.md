# Zeek session pipeline patch report

- Fixed `scripts/parse_public_pcaps.py` so Zeek is detected using the environment PATH that includes `/opt/zeek/bin`.
- Fixed parser to pass absolute PCAP paths when running Zeek from per-case log directories.
- Added `parser_source=zeek_conn` for Zeek conn.log records and `parser_source=tshark_fallback` for packet fallback records.
- Added `suricata_evidence_available` flag to session cards and classification records.
- Optimized session-card context feature computation by precomputing per-source/per-destination statistics.
- Prompt records now include parser/evidence fields and use evidence-first policy.
- Zeek rebuild output confirms all rebuilt classification records use `zeek_conn`.
