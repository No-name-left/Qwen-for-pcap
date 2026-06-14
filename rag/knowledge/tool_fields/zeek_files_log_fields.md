---
doc_id: "zeek_files_log_fields"
title: "Zeek files.log fields"
category: "tool_fields"
attack_types: ["normal", "exploit", "trojan_callback", "other_attack"]
attack_stages: ["none", "initial_access", "command_and_control"]
keywords: ["Zeek", "files.log", "filename", "mime_type", "file download"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Zeek files.log fields

## Evidence

Zeek files.log describes files transferred over observed protocols, including names, MIME types, hashes when configured, and source protocol context.

## Judgment

File transfer evidence can support malware download, exploit payload staging, or exfiltration when paired with suspicious URI, MIME type, alert, or direction.

## Stage mapping

Downloads tied to compromise may map to initial_access; malware retrieval or callback chains may map to command_and_control.

## Boundaries

File transfer is common. Do not label a file malicious without signature, suspicious path, known bad metadata, or surrounding attack behavior.
