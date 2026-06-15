# RAG fact check report

## Reviewed factual-risk areas

- weak evidence as strong attack: No broad pattern found; weak-evidence docs recommend normal/none or low confidence.
- protocol anomaly equals attack: No broad pattern found; protocol anomaly docs explicitly require corroboration.
- SMB port 445 equals exploit: No broad pattern found; SMB docs say port 445 alone is insufficient.
- high volume equals DoS: No broad pattern found; high-volume docs distinguish normal traffic from DoS.
- periodic connection equals C2: No broad pattern found; periodic-connection docs require context.
- DOUBLEPULSAR ordinary exploit only: No issue; DOUBLEPULSAR docs describe backdoor/implant/post-exploitation behavior.
- case-level as event-level truth: No issue; aggregation docs warn against strict event-level use of case-level labels.
- Suricata alert always correct: No issue; Suricata docs call alerts IDS evidence and require context.
- current test answers or expected labels: No forbidden answer/label tokens found.

## Targeted risky-phrase scan

- No risky equivalence phrases found.

## Leakage scan

- No forbidden leakage terms found.

## Fixes made in this final pass

- Refreshed source grounding for STRRAT, DOUBLEPULSAR, MS17-010, protocol anomaly, Suricata EVE, Zeek conn.log, and core ATT&CK stages.
- Added deprecated-source notes and stable replacements for failed STRRAT and DOUBLEPULSAR-related URLs.
- No factual rewrite of the 71-document RAG library was required.

## Conclusion

- Factual review result: pass.
- Ready for chunk/index/query builder: yes.
