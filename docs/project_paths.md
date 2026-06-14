# 项目路径说明

本文档记录当前推荐路径，并标注已存在、planned / to be generated、legacy 三类状态。

## 输入

| path | status | note |
| --- | --- | --- |
| `datasets/raw/` | exists | 原始公开 PCAP 数据目录。 |
| `outputs/parsed/` | exists | tshark / Zeek / Suricata 离线解析结果。 |

## 中间结果

| path | status | note |
| --- | --- | --- |
| `outputs/session_cards/session_cards_all.json` | planned / to be generated | 正式 session card 全量输出。 |
| `outputs/session_cards/llm_session_cards_all.json` | planned / to be generated | 给 LLM 使用的脱敏 session card。 |
| `outputs/rag_queries/` | exists | RAG query 输出目录；需确认是否已迁移到 session-level。 |
| `outputs/rag_retrieval/` | exists | RAG retrieval 输出目录；需确认是否已迁移到 session-level。 |
| `outputs/event_cards/` | archived | 旧 event-card 输出已移动到 `_non_mainline_archive/legacy_event_card_pipeline/outputs/event_cards/`。 |
| `outputs/evaluation/` | archived | 旧本地评估和映射文件已移动到 `_non_mainline_archive/legacy_event_card_pipeline/outputs/evaluation/`，不能作为 prompt/RAG 的答案来源。 |

## RAG

| path | status | note |
| --- | --- | --- |
| `rag/knowledge/` | exists | RAG 知识库。部分文档仍有 event-level / legacy 标签口径，使用前需复核。 |
| `rag/metadata/rag_manifest.csv` | exists | RAG 文档 manifest。 |
| `rag/metadata/source_manifest.csv` | exists | RAG 来源 manifest。 |
| `rag/chunks/rag_chunks.jsonl` | exists | RAG chunks。 |
| `rag/index/keyword_index.json` | exists | keyword + metadata retrieval baseline。 |
| `rag/reports/` | exists | RAG 审查和测试报告。 |
| `rag/reports/rag_final_coverage_review.md` | exists | 当前保留的 RAG final report。 |
| `rag/reports/rag_fact_check_report.md` | exists | 当前保留的 RAG fact-check report。 |
| `rag/reports/rag_source_grounding_report.md` | exists | 当前保留的 RAG source-grounding report。 |
| `rag/reports/qwen*` 和旧测试报告 | archived | 已移动到 `_non_mainline_archive/old_reports/` 或 `_non_mainline_archive/legacy_qwen14b/`。 |

## Prompt

用户曾提到 `微型testv2/`，但当前项目实际存在的是 `微型test_v2/`。后续建议统一使用 `微型test_v2/`。

推荐正式路径：

| path | status | note |
| --- | --- | --- |
| `微型test_v2/outputs/prompts_qwen35_27b_stage_no_rag/` | planned / to be generated | 第一阶段 no-RAG prompt。 |
| `微型test_v2/outputs/prompts_qwen35_27b_stage_rag/` | planned / to be generated | 第一阶段 RAG prompt。 |
| `微型test_v2/outputs/prompts_qwen35_27b_technique_no_rag/` | planned / to be generated | 第二阶段 no-RAG prompt。 |
| `微型test_v2/outputs/prompts_qwen35_27b_technique_rag/` | planned / to be generated | 第二阶段 RAG prompt。 |

当前历史路径：

| path | status | note |
| --- | --- | --- |
| `微型test_v2/outputs/prompts_qwen35_27b_no_rag/` | archived | 旧 event-level no-RAG prompt 已移动到 `_non_mainline_archive/old_prompts/`。 |
| `微型test_v2/outputs/prompts_qwen35_27b_rag/` | archived | 旧 event-level RAG prompt 已移动到 `_non_mainline_archive/old_prompts/`。 |
| `微型test_v2/outputs/prompts_qwen35_27b_no_rag_b2/` | archived | 旧批次 prompt 已移动到 `_non_mainline_archive/old_prompts/`。 |
| `微型test_v2/outputs/prompts_qwen35_27b_rag_b2/` | archived | 旧批次 RAG prompt 已移动到 `_non_mainline_archive/old_prompts/`。 |

## 输出

| path | status | note |
| --- | --- | --- |
| `outputs/submissions/stage1_submission.csv` | planned / to be generated | 第一阶段正式 CSV。 |
| `outputs/submissions/stage2_submission.csv` | planned / to be generated | 第二阶段正式 CSV。 |
| `outputs/submissions/submission_export_report.md` | planned / to be generated | 人工检查报告，保存理由和证据。 |

## 归档

| path | status | note |
| --- | --- | --- |
| `_non_mainline_archive/` | exists | 统一非主线归档目录。不要删除。 |
| `_non_mainline_archive/archive_manifest.md` | exists | 实际移动文件 manifest。 |
| `_non_mainline_archive/archive_manifest.json` | exists | 机器可读 manifest。 |
| `_non_mainline_archive/dry_run_candidates.md` | exists | dry-run 候选报告。 |
| `_non_mainline_archive/legacy_qwen14b/` | exists | Qwen3-14B 旧 prompt、结果、脚本和报告。 |
| `_non_mainline_archive/legacy_event_card_pipeline/` | exists | 旧 event-card pipeline 输出、schema、旧 taxonomy 和映射。 |
| `_non_mainline_archive/old_prompts/` | exists | 旧 event-level prompt。 |
| `_non_mainline_archive/partial_runs/` | exists | 旧 event-level partial run / result。 |
| `_non_mainline_archive/old_reports/` | exists | 旧报告。 |
| `_non_mainline_archive/old_scripts/` | exists | 旧脚本。 |
| `outputs/archive/` | empty or legacy container | 旧内容已迁移到 `_non_mainline_archive/`，目录可保留。 |
| `微型test_v1/` | archived content | 早期小 demo 文件已移动到 `_non_mainline_archive/legacy_event_card_pipeline/微型test_v1/`。 |
| `微型test_v2/outputs/event_cards/` | archived | 历史微型测试 event-card 抽样已移动到 `_non_mainline_archive/legacy_event_card_pipeline/微型test_v2/outputs/event_cards/`。 |

## 配置

| path | status | note |
| --- | --- | --- |
| `configs/competition_label_schema.yaml` | exists after migration | 官方标签、CSV 字段和 fallback 规则。 |
| `configs/llm_qwen35_27b.yaml` | exists | Qwen3.5-27B env-based 配置。 |
| `configs/attack_taxonomy.yaml` | archived | 旧内部语义标签配置已移动到 `_non_mainline_archive/legacy_event_card_pipeline/configs/attack_taxonomy.yaml`。 |

## 仍需人工确认

| path | status | note |
| --- | --- | --- |
| `scripts/run_qwen_openai_compatible_isolated.py` | uncertain / not moved | 非白名单替代 runner，脚本保留原位，建议人工确认是否仍需保留。 |
