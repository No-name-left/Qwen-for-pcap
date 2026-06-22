# VM operation notes

GitHub is the only code source. The competition VM is a runtime target: clone the repository into `/data/code/Qwen-for-pcap`, check out a reviewed commit, and use `git pull` for updates. Do not keep long-lived edits in an uploaded ZIP tree.

Recommended layout:

```text
/data/code/Qwen-for-pcap     tracked code and lightweight metadata
/data/models/Qwen3.5-27B     model weights; never commit
/data/competition_input      official PCAP input; never train on or commit
/data/logs                   service/pipeline logs
/data/cache                  Zeek/vLLM/runtime cache
```

Copy values from `configs/env.vm.example` into an untracked `.env.local`. Never paste a real key into YAML, shell scripts, reports, or Git history.

Suggested deployment sequence:

```bash
cd /data/code/Qwen-for-pcap
git pull --ff-only
bash scripts/check_env.sh
python3 scripts/test_rag_retrieval.py
RUNTIME_PROFILE=ascend_openeuler_qwen35_27b bash run_stage1.sh --parsed-dir /data/cache/parsed
```

Stage1 submits stage codes; stage2 submits technique codes. Both infer techniques first. Do not copy official example/test PCAP records into RAG, SFT data, or public evaluation assets.
