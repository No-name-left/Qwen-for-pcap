# Offline Debug Playbook

This playbook is for the Phase-1 VM workflow when the environment may be offline. It assumes the repository, model weights, Zeek or Docker Zeek image, TShark, RAG chunks, and Python dependencies are already present on the VM.

## 1. 正式数据到达后的推荐流程

```bash
# 1. dry-run，只解析，不调用模型
bash run_phase1_vm.sh --input <PCAP_DIR> --output-dir <OUT_DRY> --granularity pcap --dry-run

# 2. 查看解析与 prompt
cat <OUT_DRY>/run_summary.md
cat <OUT_DRY>/session_cards/pcap_level_records_report.md
cat <OUT_DRY>/rag/retrieval_report.md
ls <OUT_DRY>/prompt_samples

# 3. 小规模模型测试
bash run_phase1_vm.sh --input <PCAP_DIR> --output-dir <OUT_API_3> --granularity pcap --base-url http://127.0.0.1:8000/v1 --model qwen3.5 --api-key EMPTY --limit 3 --no-dry-run

# 4. 先用 100/1000 条测吞吐和 vLLM 稳定性
bash run_phase1_vm.sh --input <PCAP_DIR> --output-dir <OUT_API_100> --granularity pcap --base-url http://127.0.0.1:8000/v1 --model qwen3.5 --api-key EMPTY --limit 100 --max-api-workers 1 --no-dry-run
cat <OUT_API_100>/inference_plan_report.md
cat <OUT_API_100>/routing_summary.csv

# 5. 对比并发 worker=2/4
bash run_phase1_vm.sh --input <PCAP_DIR> --output-dir <OUT_API_100_W2> --granularity pcap --base-url http://127.0.0.1:8000/v1 --model qwen3.5 --api-key EMPTY --limit 100 --max-api-workers 2 --no-dry-run

# 6. 全量运行：显式启用高置信规则直出、并发和断点续跑
bash run_phase1_vm.sh --input <PCAP_DIR> --output-dir <OUT_FULL> --granularity pcap --base-url http://127.0.0.1:8000/v1 --model qwen3.5 --api-key EMPTY --llm-routing high-confidence-skip --max-api-workers 2 --resume --official-metadata-source representative --submission-timezone Asia/Shanghai --no-dry-run

# 7. 查看提交文件
cat <OUT_FULL>/official_submission.csv
```

Default behavior stays conservative: `--max-api-workers 1`, `--llm-routing all`, and resume off unless `--resume` is provided. Use `--max-api-workers 4` only after small-batch latency and failure rates look stable. `--llm-routing none` never initializes the API and is useful for smoke/extreme offline checks, not for default quality runs.

If the model run already finished and only the official table needs to be regenerated:

```bash
python3 scripts/export_official_submission.py --output-dir <OUT_FULL> \
  --submission-label-level stage \
  --pcap-id-source pcap_id \
  --official-metadata-source representative \
  --submission-timezone Asia/Shanghai
```

For a technique-level future round:

```bash
python3 scripts/export_official_submission.py --output-dir <OUT_FULL> \
  --submission-label-level technique
```

If the organizer provides an empty submission template, prefer copying its metadata columns:

```bash
python3 scripts/export_official_submission.py --output-dir <OUT_FULL> \
  --submission-template <TEMPLATE_CSV_OR_XLSX>
```

`--submission-template` copies only `pcap编号` or `文件名`, `开始时间`, `结束时间`, `源IP`, `源端口`, `目的IP`, and `目的端口`. Any answer/label column in that template is ignored; label and reason still come from the validated model prediction.

For shard runs, use 0-based shard indexes and merge with the full dry-run selected records:

```bash
# Example: run shard 0 and 1 separately
bash run_phase1_vm.sh --input <PCAP_DIR> --output-dir <OUT_SHARD_0> --granularity pcap --num-shards 2 --shard-index 0 --base-url http://127.0.0.1:8000/v1 --model qwen3.5 --api-key EMPTY --llm-routing high-confidence-skip --max-api-workers 2 --resume --no-dry-run
bash run_phase1_vm.sh --input <PCAP_DIR> --output-dir <OUT_SHARD_1> --granularity pcap --num-shards 2 --shard-index 1 --base-url http://127.0.0.1:8000/v1 --model qwen3.5 --api-key EMPTY --llm-routing high-confidence-skip --max-api-workers 2 --resume --no-dry-run

# Merge predictions in original selected_records order and rebuild official submission
python3 scripts/merge_phase1_shards.py \
  --shard-output-dir <OUT_SHARD_0> \
  --shard-output-dir <OUT_SHARD_1> \
  --output-dir <OUT_MERGED> \
  --records-json <OUT_DRY>/session_cards/selected_records.json \
  --parse-summary <OUT_DRY>/parsed/parse_all_summary.json \
  --official-metadata-source representative \
  --submission-timezone Asia/Shanghai
```

## 2. 常用诊断文件说明

| Path | 用途 |
|---|---|
| `run_summary.md` | 总览状态、粒度、prompt/RAG/API 计数、official submission 导出状态和安全边界。 |
| `phase1_predictions.csv` | 调试用预测表，包含 `pcap_id`、`pcap_name`、`record_id`、`stage_code`、`technique_guess`、`confidence`、`reason` 等扩展字段。不要直接作为官方提交表。 |
| `official_submission.csv` | 官方提交 CSV，严格 9 列：`pcap编号`、起止时间、五元组、阶段/正常编号、研判理由。Phase-1 默认输出 `TA43/TA01/TA03/TA11/TN01`。无模板时默认用 `--official-metadata-source representative`；有主办方待填写模板时推荐 `--submission-template`。 |
| `official_submission.xlsx` | 如果 `openpyxl` 可用，同步生成的官方提交 Excel。 |
| `predictions.jsonl` | 验证后的模型 JSON 输出，一行一条，适合重新导出或排查 JSON 字段。 |
| `failed_records.jsonl` | API 调用、模型输出解析或字段校验失败的记录。 |
| `routing_summary.csv` | 每条记录最终路由：resume skip、rule_direct 或 llm，并保留 score、margin、strength、conflict flags、latency。 |
| `inference_plan_report.md` | 大规模运行摘要：rule-direct/LLM 计数、失败数、吞吐、平均 latency、估算串行天数、worker、resume、shard。 |
| `parse_errors.jsonl` | Zeek/TShark warning、fallback、supplement 失败等解析问题。 |
| `candidate_scores.csv` | 规则候选、top candidates、score margin、evidence strength、预测结果和 conflict flags。 |
| `candidate_score_report.md` | 候选评分和冲突复核数量摘要。 |
| `session_cards/pcap_level_records.json` | PCAP 模式的一包一条聚合证据，是 prompt 的主要结构化输入。 |
| `session_cards/session_cards_report.md` | session card 生成概况和覆盖摘要。 |
| `rag/retrieval_report.md` | RAG 命中、targeted boundary chunk 和 top-k 检索情况。 |
| `prompts/` | 全部 prompt。内容可能较多，主要用于逐条复核。 |
| `prompt_samples/` | 默认前 5 条 prompt 样本，适合快速确认字段、RAG 和 token budget。 |

## 3. 无标签正式数据下能调什么

可以调：

- `--max-prompt-tokens`，控制 prompt token budget。
- `--rag-top-k`，控制 RAG top-k 和 boundary chunk 数量。
- candidate evidence selection 数量，优先保留 PCAP-level 的代表性强证据。
- `--granularity pcap|session`，Phase-1 正式提交推荐 `pcap`。
- `--submission-label-level stage|technique`，Phase-1 默认 `stage`。
- `--official-metadata-source representative|aggregate`，无模板时推荐 `representative`。
- `--submission-timezone UTC|Asia/Shanghai`，默认 `Asia/Shanghai`。
- `--max-api-workers`，先用 1/2/4 小批量对比吞吐和失败率。
- `--llm-routing all|high-confidence-skip|none`，默认 `all`；大规模可试 `high-confidence-skip`，`none` 只适合 smoke。
- `--rule-direct-min-score`、`--rule-direct-min-margin`、`--rule-direct-min-strength`、`--rule-direct-max-conflicts`，只在无标签情况下做保守阈值调整。
- `--num-shards` / `--shard-index`，多进程或多 VM 分片时使用。
- `--max-completion-tokens` 和 `--compact-reason`，可减少输出长度；默认不改变 prompt 内容。
- 实验开关是否启用，例如 critic prompt 生成；不稳定 calibration 不应进入默认推理链路。

不建议在无标签正式数据上盲目调：

- 训练、SFT、LoRA。
- 大规模规则硬编码。
- 把正式数据里的单个文件名、IP、hash、路径写死成标签规则。
- 把答案表作为训练、RAG、prompt 或推理输入；答案只能在推理完成后用于离线评估。
- aggressive calibration，尤其是把弱证据放大成攻击或正常硬判定。

## 4. 离线修改 RAG / prompt 的建议

相对安全的范围：

- 根据正式数据的协议分布补充通用 RAG 边界说明，例如“仅有周期性 TLS 不足以证明 C2”这类可复用边界。
- 调整 prompt 中解释文字和候选展示顺序，保持 stage-first 输出约束。
- 调整 evidence top-k，确保强证据、反证和 boundary RAG 优先保留。
- 用 dry-run 对比 `prompt_samples/`、`rag/retrieval_report.md` 和 `candidate_scores.csv`，确认修改只改变证据展示，不写入标签答案。

不要做：

- 不要把未标注正式数据中的单个文件名、IP、hash、URI 路径写死成标签规则。
- 不要在无标签情况下做 aggressive calibration。
- 不要把 raw payload、完整 HTTP body、API key、cookie、authorization header 或明文凭据写入 prompt、RAG 或提交理由。

## 5. 离线环境自检

```bash
python3 scripts/check_offline_readiness.py \
  --model-path /data/models/Qwen3.5-27B \
  --outputs-dir /data/outputs \
  --base-url http://127.0.0.1:8000/v1 \
  --model qwen3.5
```

如果本地模型服务尚未启动，只检查文件和工具：

```bash
python3 scripts/check_offline_readiness.py --no-check-api
```

`openpyxl` 缺失时 CSV 仍可用，脚本会给 warning；Zeek/Docker Zeek、TShark、模型目录、RAG chunks、runner、official exporter 和输出目录写权限属于正式离线运行的关键项。
