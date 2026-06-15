# Mixed small API fix summary

- API actually run this round: false
- New API calls this round: 0
- Technique final success/failure: 7/3
- Stage final success/failure: 1/9
- Main failure cause: timeout plus bounded-run interruption; no auth, quota, JSON parse, or illegal-code evidence was found.
- Portscan scan_group final technique is `TA43_01`: true
- CSV exported: false
- Expand to 30 records: no; rerun only the failed mixed-small records first.
- Prompt fix needed first: no obvious prompt defect from the successful records.
- Runner fix needed first: yes; this commit adds record-id rerun, failed-record output, retry-once, and continue-on-error controls.
- Bastion prep usability: usable for deployment rehearsal and failure-only rerun planning, not yet sufficient as a complete model-result CSV.
- Verdict: `PARTIAL_SUCCESS_USABLE_FOR_BASTION_PREP`
