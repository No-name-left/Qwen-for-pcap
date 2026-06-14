---
doc_id: "signature_web_sql_injection"
title: "SQL injection signature"
category: "signatures"
attack_types: ["exploit"]
attack_stages: ["initial_access"]
keywords: ["SQL injection", "SQLi", "UNION SELECT", "OR 1=1", "http_uri"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# SQL injection signature

## Evidence

SQL injection signatures indicate attempts to manipulate database queries through web parameters. URI evidence may include UNION SELECT, quote escaping, OR conditions, stacked queries, or database function names.

## Judgment

Classify as exploit with subtype sql_injection when the request or alert supports SQLi.

## Stage mapping

SQLi maps to initial_access because it attacks the web application to access data or control logic.

## Boundaries

Some strings may appear in benign testing or encoded content. Use alert context and repeated malicious parameters.
