# SFT data readiness report

- Candidate records: 181
- Recommended after manual review: 171
- Recommended counts by code: `{"TA01_01": 30, "TA01_02": 30, "TA11_02": 80, "TA43_01": 1, "TN01_01": 30}`
- Not recommended counts by code: `{"TN01_01": 10}`
- Already usable candidates: TA43_01, TA11_02, TA01_01, TA01_02, TN01_01.
- Not ready: TA43_02, TA03_01, TA11_01 due missing reliable local samples.
- Do not start SFT yet unless high-confidence labels are expanded and manually reviewed.
- Suggested first SFT target: 50-100 high/medium reviewed samples per covered class, then add missing-class data.
