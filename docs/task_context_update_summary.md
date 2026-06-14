# 任务上下文更新总结

更新时间：2026-06-10

## 1. 检查了哪些文件

本次检查覆盖了项目根目录下的说明、配置、RAG 和历史输出记录，包括：

- `README.md`
- `rag/README.md`
- `rag/chunks/README.md`
- `rag/index/README.md`
- `rag/sources/README.md`
- `scripts/rag_README_NEXT_STEPS.md`
- `configs/attack_taxonomy.yaml`
- `configs/llm_qwen35_27b.yaml`
- `schemas/event_card.schema.json`
- `schemas/llm_output.schema.json`
- `outputs/event_cards/`
- `outputs/evaluation/`
- `outputs/rag_queries/`
- `outputs/rag_retrieval/`
- `outputs/archive/`
- `微型test_v1/`
- `微型test_v2/`

## 2. 修改了哪些文件

- `README.md`
- `rag/README.md`
- `rag/chunks/README.md`
- `rag/index/README.md`
- `rag/sources/README.md`
- `scripts/rag_README_NEXT_STEPS.md`
- `configs/llm_qwen35_27b.yaml`

## 3. 新增了哪些文件

- `docs/current_task_definition.md`
- `docs/project_paths.md`
- `docs/project_context_migration_scan_report.md`
- `docs/task_context_update_summary.md`
- `configs/competition_label_schema.yaml`

## 4. Diff 摘要

修改前后差异集中在说明和配置层：

- 重写 `README.md`，将项目主线从 legacy event-level JSON pipeline 更新为 session-level 官方编号和 CSV 提交流程。
- 重写 `rag/README.md`，将 RAG 目标改为支持 session-level `stage_code` / `technique_code` 判断。
- 更新 `rag/chunks/README.md`、`rag/index/README.md`、`rag/sources/README.md`，补充安全边界、keyword + metadata baseline 和 session-level 口径。
- 重写 `scripts/rag_README_NEXT_STEPS.md`，将下一步从 event-card query / JSON 测试改为 session card、两阶段 prompt、Qwen3.5-27B 和 CSV exporter。
- 更新 `configs/llm_qwen35_27b.yaml`，明确使用环境变量读取 base URL、API key 和模型名，不写真实 token。
- 新增 `configs/competition_label_schema.yaml`，记录官方标签、CSV 字段、legacy semantic label 映射和 fallback 规则。
- 新增 `docs/` 下 4 个上下文文档，记录扫描结果、当前任务定义、路径状态和迁移总结。

未修改原始数据、RAG 知识库正文、event cards、session cards、解析结果或 archive。

## 5. 哪些旧术语已替换

主说明和 RAG 说明中已将正式口径更新为：

- `event` -> `session`
- `event card` -> `session card`
- `attack_type` / `attack_stage` final output -> `stage_code` / `technique_code`
- `event_results.json` final output -> `stage1_submission.csv` / `stage2_submission.csv`
- `pcap_summary.json` scoring core -> human-readable auxiliary report
- `Qwen3-14B` mainline -> legacy; current mainline is `Qwen3.5-27B`
- `accuracy` as primary metric -> macro-F1 / per-class F1, or qualitative comparison when labels are unavailable

## 6. 哪些旧内容保留为 legacy

以下内容未删除，保留为历史产物或迁移参考：

- `configs/attack_taxonomy.yaml`
- `schemas/event_card.schema.json`
- `schemas/llm_output.schema.json`
- `outputs/event_cards/`
- `outputs/evaluation/`
- `outputs/archive/`
- `微型test_v1/`
- `微型test_v2/outputs/event_cards/`
- `微型test_v2/outputs/prompts_qwen35_27b_no_rag*/`
- `微型test_v2/outputs/prompts_qwen35_27b_rag*/`

## 7. 当前推荐主流程

```text
PCAP
-> tshark / Zeek / Suricata 解析
-> sessionization / session card
-> deterministic RAG query builder
-> RAG retriever
-> Qwen3.5-27B session-level classification
-> stage / technique code prediction
-> competition CSV submission
-> human-readable analysis report
```

## 8. 当前推荐输出格式

最终推荐输出为 CSV：

- `outputs/submissions/stage1_submission.csv`
- `outputs/submissions/stage2_submission.csv`

推荐字段：

- stage 1: `pcap_id`, `session_id`, `stage_code`
- stage 2: `pcap_id`, `session_id`, `technique_code`

研判理由、置信度、证据和 RAG 文档 id 应保留在 `outputs/submissions/submission_export_report.md` 或本地审计文件中，不应混入正式 CSV，除非官方模板允许。

## 9. 当前推荐路径

详见 `docs/project_paths.md`。核心路径包括：

- `datasets/raw/`
- `outputs/parsed/`
- `outputs/session_cards/`
- `outputs/rag_queries/`
- `outputs/rag_retrieval/`
- `rag/knowledge/`
- `rag/chunks/rag_chunks.jsonl`
- `rag/index/keyword_index.json`
- `outputs/submissions/`
- `outputs/archive/`

## 10. 路径不一致

发现路径不一致：

- 用户背景中出现 `微型testv2/`
- 当前项目实际存在 `微型test_v2/`

建议后续统一使用 `微型test_v2/`，并逐步修正文档或脚本中的无下划线路径。

## 11. 需要人工确认的地方

- 是否新增 `schemas/session_card.schema.json` 和 `schemas/competition_output.schema.json`。
- 是否将 `scripts/build_event_cards.py` 改造成 session card builder，或新增 `scripts/build_session_cards.py`。
- 是否迁移 Qwen prompt builder，使其输出 stage / technique 两套 prompt。
- 是否新增 CSV exporter，并严格对齐官方模板。
- `outputs/archive/qwen35_27b_*` 中的历史输出是否可作为报告引用，需要人工确认后再写入正式报告。
- RAG `knowledge/aggregation_policy/` 中旧 event-level / PCAP-level 聚合文档是否需要逐篇改写为 session-level policy。

## 12. Clear Verdict

`TASK_CONTEXT_UPDATED`
