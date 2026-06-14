---
doc_id: competition_session_and_scan_group_policy
title: Session and scan-group output policy
category: competition_labels
attack_types: [normal, port_scan, exploit, backdoor, trojan_callback, c2, other_attack]
attack_stages: [none, reconnaissance, initial_access, persistence, command_and_control]
keywords: [session, scan_group, TA43_01, record_id, session_id, classification record, CSV]
source_type: official_or_distilled
safe_for_llm: true
---

# Session and scan-group output policy

The formal unit is one judgment per session, except clear multi-port port scanning can be merged into one `scan_group` classification record.

When a `scan_group` is emitted, its member sessions should not also be emitted as independent final output records. This avoids duplicate rows for the same port-scan behavior.

Each classification record must have a stable `record_id`. For CSV export, `session_id` can use the session id for normal sessions and the scan-group id for merged scan groups.

PCAP files are independent. Do not aggregate evidence across PCAPs.

The RAG query and model prompt should use `record_id`, not old `event_id`.
