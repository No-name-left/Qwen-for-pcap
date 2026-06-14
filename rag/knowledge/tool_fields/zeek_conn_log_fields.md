---
doc_id: "zeek_conn_log_fields"
title: "Zeek conn.log fields"
category: "tool_fields"
attack_types: ["normal", "port_scan", "exploit", "backdoor", "trojan_callback", "c2", "other_attack"]
attack_stages: ["none", "reconnaissance", "initial_access", "persistence", "command_and_control"]
keywords: ["Zeek", "conn.log", "conn_state", "failed_conn_rate", "orig_bytes", "resp_bytes"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Zeek conn.log fields

## Evidence

Zeek conn.log summarizes connections rather than individual packets. conn_count, services, conn_state distribution, duration, orig_bytes, resp_bytes, and failed_conn_rate describe connection behavior.

## Judgment

Use conn.log to judge connection success, failures, byte direction, and service inference. Many S0, REJ, RSTOS0, or similar states can support scanning or failed access attempts.

## Stage mapping

Connection summaries can support reconnaissance, initial_access, or command_and_control depending on surrounding evidence.

## Boundaries

conn.log may omit application details and may infer services imperfectly. Do not treat a single failed connection as a strong attack.

## Source grounding

Grounded by Zeek official conn.log and DNS/common log documentation. Zeek `conn.log` is a connection summary, not a packet-level log. Fields such as `conn_state`, `service`, `duration`, `orig_bytes`, `resp_bytes`, and failed-connection statistics help distinguish scans, failed access, sustained sessions, and weak evidence.
