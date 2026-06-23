# Session card observable evidence review

## Scope and verdict

Reviewed `build_session_cards.py`, `parse_public_pcaps.py`, classification-record, RAG-query/retrieval, prompt and CSV-export paths, existing `outputs/parsed`, `outputs/session_cards`, documentation, and the requested official-sample locations. Before this change, session cards carried connection features plus small Zeek HTTP/DNS/TLS summaries. There was no bounded HTTP-body path, so a Wireshark-visible string such as `xp_cmdshell` could not reach a card, record, query, or prompt.

The implementation now keeps Zeek `conn.log` as the session spine, uses Zeek application logs first, and adds a streaming TShark selected-field supplement. Complete bodies and files are never persisted. Only redacted, bounded context around classification-relevant text is retained.

## 1. Field coverage

Baseline fields were: session identity and five-tuple, time/duration, packet/byte counts, connection state/history, Zeek UID/TCP stream, small `http_summary`, `dns_summary`, `tls_summary`, and same-PCAP fanout/failure counts. Classification records retained only those fields; scan-group records retained mostly scan statistics.

The enhanced stable card adds:

- Visibility: `payload_visibility`, `observable_payload_available`, `encrypted_protocol`, `extraction_warnings`, `evidence_limits`, and `evidence_mapping`.
- HTTP metadata: methods, hosts, bounded URI/full-URI samples, status codes, user agents, referrers, content types, request/response body lengths, Cookie/Authorization presence booleans, multipart/upload hints, and a body-observed boolean.
- Safe content: bounded redacted request/response snippets, suspicious payload snippets, suspicious parameter names/values, and URI-pattern names.
- Structured indicators: `exploit_indicators`, `vuln_scan_indicators`, `auth_indicators`, `implant_indicators`, `backdoor_access_indicators`, and `c2_indicators`.
- File metadata: `transferred_files_summary`; no extracted content.
- Same-PCAP aggregate: time range, counts, top endpoints/ports, protocols, bounded HTTP/DNS/SNI samples, indicator counts, scan/auth/beacon summaries.

These fields are retained by session classification records. Scan groups merge bounded observable evidence from their members so vulnerability probes are not lost when member sessions are suppressed.

## 2–5. Closed-set coverage and gaps

| Technique | Baseline adequacy | New useful evidence | Important limit |
|---|---|---|---|
| `TA43_01` | Relatively strong | fanout, failures, scan grouping | A port list does not imply vulnerability scanning. |
| `TA43_02` | Weak | scanner UA, NSE/service probes, CVE/probe paths, URI fanout, 404 ratio | A scanner name or one admin path is weak. |
| `TA01_01` | Weak | Zeek SSH/FTP auth fields, repeated HTTP login paths/status, credential-field presence | Connection failure is not password failure; no password values are stored. |
| `TA01_02` | Weakest critical gap | bounded body/URI contexts, injection/traversal/XSS/command/encoded indicators including `xp_cmdshell` | Visible text proves transmission, not execution. Scanner probes can resemble exploit attempts. |
| `TA03_01` | Weak | multipart/upload, suspicious extension, Zeek file direction/MIME, executable/archive transfer | Upload does not prove installation or persistence. |
| `TA11_01` | Weak | recognizable webshell path, command parameter and interactive-command context | Initial injection is usually `TA01_02`; deployment is `TA03_01`. |
| `TA11_02` | Partial metadata only | periodic/fixed endpoint, small repeated transfers, DNS/SNI repetition, bounded interval/score | Updates and telemetry can be periodic; encryption alone is insufficient. |
| `TN01_01` | Moderate but overly dependent on missing evidence | explicit visibility limits and stronger negative boundaries | Hidden payload must not be treated as normal evidence. |

PCAP-visible evidence previously omitted included Zeek `files.log`, `ssh.log`, `ftp.log`, HTTP body lengths/referrer/MIME, selected TShark HTTP method/full URI/status/content metadata, header presence, limited plaintext-body contexts, form-field presence, and cross-session interval/repetition summaries. `x509.log` was reviewed but is not promoted into per-session cards: certificate-chain mapping is not reliable enough in all captures and adds little beyond bounded TLS/SNI metadata for this closed set. A future PCAP-level certificate summary is safer than duplicating full subjects/issuers per session.

## 6. Fields selected for cards

Current-session evidence is retained when it can be bounded and mapped by Zeek UID, TCP stream, or bidirectional five-tuple. Mapping confidence is explicit. Source attribution is:

- Zeek: connection/session fields, HTTP/DNS/TLS metadata, body lengths, SSH/FTP auth metadata, file names/MIME/direction.
- TShark selected fields: reassembled plaintext HTTP body context, method/full URI/status/user agent/referrer/content type, form fields, and Cookie/Authorization presence only.
- Same-PCAP computation: fanout/failure, repeated auth/backdoor endpoints, URI/404 aggregation, intervals/beacon score, and `pcap_summary`.

## 7. Evidence deliberately excluded

The pipeline does not retain raw PCAPs, complete bodies, raw packet JSON, complete uploads/downloads, extracted files, binaries, TLS keys, Cookie/Authorization values, passwords, tokens, JWTs, or answer-table fields. It also avoids reputation and cross-PCAP linkage. Full TLS certificate chains, arbitrary response bodies, and all benign body text were excluded because they consume budget, can be sensitive, and add unstable or weak classification value.

Default Zeek HTTP/FTP output is post-sanitized for URI secrets, HTTP basic-auth fields, and FTP `PASS` arguments. TShark body fields are streamed through the reducer and are never written raw.

## 8. PCAP-level-only fields

Time range, total sessions, top endpoints/ports, protocols, bounded host/query/SNI samples, indicator counts, scan-source count, aggregate auth count, and beacon-score summary belong in `pcap_summary`. They are computed once conceptually and attached as a bounded context object; prompts include it last and truncate it before current-session evidence. Full session lists, complete DNS/SNI lists, and certificate inventories are not repeated.

## 9. Prompt versus RAG/scoring use

Prompts expose the visibility state, current HTTP evidence, suspicious snippets, positive structured indicators, file metadata, warnings, and a compact PCAP summary under `OBSERVABLE_EVIDENCE_FROM_PCAP`. False/empty indicator members are removed from prompt text but remain in card JSON. `evidence_mapping` is shown to calibrate confidence.

`targeted_rag_triggers`, `targeted_boundary_cards`, and `indicator_fields_used` are retrieval/scoring metadata. Indicator fields trigger the requested scan, exploit, auth, implant, access/callback, C2/normal, and encrypted-visibility cards. Prompt manifests record these plus `prompt_budget_summary`. The record remains primary; network indicators do not prove host-side success.

## Requested-string audit

Before implementation, repository searches of available session cards, classification records, prompts, parsed logs, and RAG queries found no official-sample `xp_cmdshell`/`exec` evidence. The requested `example-s3-0623` archive/directory was not present locally, so the exact official packet could not be inspected.

The safe controlled regression transmitted inert `;exec master..xp_cmdshell 'whoami';` text. `xp_cmdshell` reached `observable_http.jsonl`, session card, classification record, RAG query, and both no-RAG/RAG prompts; the adjacent test token became `[REDACTED]`. This closes the identified data-path gap without preserving a complete payload.

## Dependencies and residual uncertainty

No Python package was installed and `openpyxl` is not required. Zeek and TShark already existed. Body extraction still depends on successful TCP/HTTP reassembly and protocol recognition; compressed, chunked, malformed, nonstandard-port, split, encrypted, HTTP/2/3, or evasively encoded content may remain metadata-only. Host execution, exploitation success, persistence, and endpoint ownership cannot be established from these fields alone.
