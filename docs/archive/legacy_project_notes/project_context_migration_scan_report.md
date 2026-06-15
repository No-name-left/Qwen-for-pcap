# 项目上下文迁移扫描报告

扫描目标：`/root/autodl-tmp/pcap_llm_demo`

扫描日期：2026-06-10

## 1. 找到的项目说明文件

关键说明和配置文件：

- `README.md`
- `rag/README.md`
- `rag/chunks/README.md`
- `rag/index/README.md`
- `rag/sources/README.md`
- `scripts/rag_README_NEXT_STEPS.md`
- `configs/attack_taxonomy.yaml`
- `configs/llm_qwen35_27b.yaml`

重要报告和记录目录：

- `rag/reports/`
- `outputs/rag_queries/`
- `outputs/rag_retrieval/`
- `outputs/event_cards/`
- `outputs/evaluation/`
- `outputs/archive/`
- `微型test_v1/`
- `微型test_v2/`

路径存在性检查：

| path | status |
| --- | --- |
| `README.md` | exists |
| `docs/` | missing before migration |
| `rag/README.md` | exists |
| `rag/chunks/README.md` | exists |
| `rag/index/README.md` | exists |
| `rag/sources/README.md` | exists |
| `scripts/rag_README_NEXT_STEPS.md` | exists |
| `configs/` | exists |
| `outputs/` | exists |
| `scripts/` | exists |
| `微型test_v2/` | exists |
| `微型testv2/` | not found |

## 2. 仍然使用旧任务定义的文件

以下文件或目录仍包含旧口径关键词，例如 `event card`、`event-level`、`attack_type`、`attack_stage`、`event_results.json`、`pcap_summary.json`、`Qwen3-14B`、`qwen3_14b`、`accuracy` 等：

- `README.md`: 原流程仍描述 `event card -> Qwen classification -> event_results.json -> pcap_summary.json`。
- `rag/README.md`: 原流程仍服务 event card，并列出旧 `normal / port_scan / exploit / backdoor / trojan_callback / c2 / other_attack`。
- `rag/chunks/README.md`: 原本仅描述 future chunk output，未说明 session-level 官方编号任务。
- `rag/index/README.md`: 原本 metadata sidecar 仍提到 `attack_type` / `attack_stage`。
- `scripts/rag_README_NEXT_STEPS.md`: 原计划围绕 event card、attack_type、attack_stage 检索。
- `configs/attack_taxonomy.yaml`: 仍是旧内部语义标签配置。
- `schemas/event_card.schema.json` 和 `schemas/llm_output.schema.json`: 仍是旧 event / JSON 输出 schema。
- `outputs/event_cards/`、`outputs/evaluation/`: 历史 event-card 与映射输出，应保留为 legacy。
- `微型test_v1/`: 早期小 demo，保留为 legacy。
- `微型test_v2/outputs/event_cards/`: Qwen 微型测试 event-card 抽样，保留为 legacy。
- `微型test_v2/outputs/prompts_qwen35_27b_no_rag*/` 和 `微型test_v2/outputs/prompts_qwen35_27b_rag*/`: 已有 Qwen3.5-27B prompt 目录，但内容仍包含 event card / legacy label 风格。
- `outputs/archive/legacy_qwen14b_*`: Qwen3-14B 历史归档，保留为 legacy。

## 3. 已经部分符合新任务定义的文件

- `configs/llm_qwen35_27b.yaml`: 已存在 Qwen3.5-27B 配置，但需要明确从环境变量读取、不要写 token、输出字段改为官方编号。
- `rag/chunks/rag_chunks.jsonl`: 已存在 chunks，可作为 keyword + metadata retrieval baseline 的输入，但源文档口径需复核。
- `rag/index/keyword_index.json`: 已存在 keyword index，可作为 baseline。
- `rag/metadata/rag_manifest.csv` 和 `rag/metadata/source_manifest.csv`: 已存在 RAG manifest。
- `outputs/rag_queries/` 和 `outputs/rag_retrieval/`: 已存在 RAG query / retrieval 输出目录，但需要确认是否已迁移到 session-level。
- `微型test_v2/outputs/rag_eval_qwen35_27b/`: 存在 Qwen3.5-27B RAG 对比相关输出，但在没有官方 session-level 标签前只能称为 qualitative comparison / local validation。

## 4. 需要修改或新增的文件

本次迁移应修改：

- `README.md`
- `rag/README.md`
- `rag/chunks/README.md`
- `rag/index/README.md`
- `rag/sources/README.md`
- `scripts/rag_README_NEXT_STEPS.md`
- `configs/llm_qwen35_27b.yaml`

本次迁移应新增：

- `docs/current_task_definition.md`
- `docs/project_paths.md`
- `docs/project_context_migration_scan_report.md`
- `docs/task_context_update_summary.md`
- `configs/competition_label_schema.yaml`

## 5. 不确定，建议人工确认的文件或内容

- `schemas/event_card.schema.json`、`schemas/llm_output.schema.json`: 是否需要新增 session-card schema 和 competition-output schema。
- `scripts/build_event_cards.py`: 是否改造为 session card builder，或另建 `scripts/build_session_cards.py`。
- `scripts/build_rag_query.py`、`scripts/retrieve_rag.py`、`scripts/build_qwen35_27b_no_rag_prompt.py`、`scripts/build_rag_augmented_prompt.py`: 是否仍默认读取 event cards，需要人工确认后迁移。
- `微型test_v2/outputs/prompts_qwen35_27b_*`: 是否可复用为正式 prompt；当前应视为 legacy-style prompt。
- `outputs/archive/qwen35_27b_*`: 存在历史/局部 Qwen3.5-27B 输出，是否能作为报告引用需要人工确认。
- `微型testv2` vs `微型test_v2`: 当前实际目录为 `微型test_v2`，建议后续统一，不再新建无下划线目录。

## 6. 扫描结论

项目已有较完整的解析、RAG、prompt 和历史实验记录，但主说明文件仍混有旧 event-level JSON pipeline。需要把正式说明统一到 session-level、官方编号、competition CSV、macro-F1 / per-class F1、Qwen3.5-27B 主线的口径，并把旧 event-card / Qwen3-14B 内容标注为 legacy。
