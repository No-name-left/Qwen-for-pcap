---
doc_id: "signature_web_xss"
title: "Cross-site scripting signature"
category: "signatures"
attack_types: ["exploit"]
attack_stages: ["initial_access"]
keywords: ["XSS", "script", "onerror", "javascript", "web exploit"]
source_type: "official_or_distilled"
safe_for_llm: true
---
# Cross-site scripting signature

## Evidence

XSS signatures indicate attempts to inject script into web pages or parameters. Evidence can include script tags, event handlers, javascript URLs, or IDS web attack categories.

## Judgment

Classify as exploit with subtype xss when the event shows active injection attempts.

## Stage mapping

XSS maps to initial_access in this taxonomy because it is a web application exploitation attempt.

## Boundaries

Reflected harmless strings and testing payloads can trigger alerts; confidence improves with alert specificity and repetition.
