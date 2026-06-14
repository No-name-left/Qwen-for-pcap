---
doc_id: "signature_directory_traversal"
title: "Directory traversal signature"
category: "signatures"
attack_types: ["exploit"]
attack_stages: ["initial_access"]
keywords: ["directory traversal", "../", "%2e%2e", "path traversal", "LFI"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Directory traversal signature

## Evidence

Directory traversal evidence includes ../ patterns, encoded traversal, attempts to read system files, or signatures naming path traversal or local file inclusion.

## Judgment

Classify as exploit with subtype directory_traversal when HTTP URI or alert evidence supports it.

## Stage mapping

The stage is initial_access because the attacker attempts to access unauthorized files or application paths.

## Boundaries

Some benign paths include dots. Require traversal semantics, sensitive target path, or alert support.
