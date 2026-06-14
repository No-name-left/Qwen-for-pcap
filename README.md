# PCAP-LLM 网络流量安全事件识别系统

本项目用于维护一个面向比赛任务的 PCAP 网络流量安全事件识别流程。当前正式口径以第二次赛前培训后的要求为准：每一个会话输出一条判断结果，不跨 PCAP 联合推断，最终提交 CSV，而不是旧版泛化 JSON。

## 快速开始

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/build_rag_chunks.py
python scripts/build_keyword_index.py
python scripts/test_rag_retrieval.py
```

Windows PowerShell 可用 `.venv\Scripts\Activate.ps1` 激活虚拟环境。调用 Qwen/OpenAI-compatible 服务前，参考 `.env.example` 设置 `LLM_BASE_URL`、`LLM_API_KEY` 和 `LLM_MODEL_NAME`，不要把真实 token 写入仓库。

GitHub 提交范围默认只包含源码、配置、文档、RAG 知识库、轻量 metadata 和项目治理文件。原始 PCAP、解析输出、模型运行结果、微型测试输出和历史归档正文均保留在本地，由 `.gitignore` 排除。

## 当前比赛任务定义

- 输入是独立 PCAP 文件。不同 PCAP 之间没有关联关系，不能互相补充证据。
- IP 和域名可能被匿名化，但同一 PCAP 内的实体关系会保留。
- 分析单位是 session，而不是旧版 event。会话切分重点依据五元组、端口变化、Zeek `conn.uid`、tshark `tcp.stream`、UDP 五元组和时间窗口。
- 第一阶段输出攻击阶段编号或正常流量编号。
- 第二阶段输出攻击技术编号或正常行为编号。
- 研判理由不计入评分，但应保留在本地分析报告中，便于人工检查。
- 评分应按 macro-F1 / per-class F1 的思路优化，不能只追求整体 accuracy 或 normal 占比。
- 当前主线模型是 Qwen3.5-27B，后续可以考虑 LoRA 学习 session-level 判别边界和输出规范。

更完整的任务说明见 `docs/current_task_definition.md`，路径说明见 `docs/project_paths.md`。

## 官方标签集合

第一阶段阶段编号：

| code | meaning |
| --- | --- |
| `TA43` | 侦察 |
| `TA01` | 初始访问 |
| `TA03` | 持久化 |
| `TA11` | 命令与控制 |
| `TN01` | 正常流量 / 上网及业务访问 |

第二阶段技术编号：

| code | meaning |
| --- | --- |
| `TA43_01` | 端口扫描 |
| `TA43_02` | 漏洞扫描 |
| `TA01_01` | 密码爆破 |
| `TA01_02` | 漏洞利用 |
| `TA03_01` | 植入后门 |
| `TA11_01` | 访问后门 |
| `TA11_02` | 木马回连 |
| `TN01_01` | 上网及业务访问 |

旧内部标签 `normal / port_scan / exploit / backdoor / trojan_callback / c2 / other_attack` 只作为 legacy internal semantic labels 或中间映射保留，不是最终提交类别。

## 推荐主流程

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

旧版流程中的 event card、`attack_type` / `attack_stage`、`event_results.json`、`pcap_summary.json` 可作为历史实验产物或辅助报告参考，但不再作为正式比赛输出口径。

## 主要目录

```text
pcap_llm_demo/
├── _non_mainline_archive/
│   ├── legacy_qwen14b/
│   ├── legacy_event_card_pipeline/
│   ├── old_prompts/
│   ├── partial_runs/
│   ├── old_reports/
│   └── old_scripts/
├── configs/
│   ├── competition_label_schema.yaml        # official stage/technique schema
│   └── llm_qwen35_27b.yaml                  # env-based LLM config
├── datasets/
│   ├── metadata/
│   └── raw/
├── docs/
│   ├── current_task_definition.md
│   ├── non_mainline_archive_summary.md
│   ├── project_context_migration_scan_report.md
│   ├── project_paths.md
│   ├── project_structure_after_archive.md
│   └── task_context_update_summary.md
├── outputs/
│   ├── parsed/
│   ├── rag_queries/
│   ├── rag_retrieval/
│   ├── session_cards/                       # planned / to be generated
│   └── submissions/                         # planned / to be generated
├── rag/
│   ├── knowledge/
│   ├── metadata/
│   ├── chunks/
│   ├── index/
│   ├── sources/
│   └── reports/
├── scripts/
└── 微型test_v2/                             # current spelling for future micro tests
```

非当前主线文件已统一归档到 `_non_mainline_archive/`。归档 manifest 位于 `_non_mainline_archive/archive_manifest.md` 和 `_non_mainline_archive/archive_manifest.json`。本仓库当前保留的顶层微型测试目录为 `微型test_v2/`；旧 `微型test_v1/` 内容已归档，后续新增脚本和报告建议统一使用 `微型test_v2/`。

## 构建 RAG

RAG 当前服务于 session-level 官方编号判断，主要提供标签边界、协议和工具字段解释、攻击技术知识、Suricata / Zeek / tshark 字段说明以及误报边界。RAG 不应包含测试答案、expected labels、MTA answers PDF 具体答案、原始 PCAP 私有路径或 API token。

现有 baseline 是 keyword + metadata retrieval：

```bash
python3 scripts/build_rag_chunks.py
python3 scripts/build_keyword_index.py
python3 scripts/test_rag_retrieval.py
```

向量或 hybrid retrieval 是未来可选增强，不是当前必要依赖。

## 生成 session cards

正式比赛口径需要 session card。推荐输出路径为：

```text
outputs/session_cards/session_cards_all.json
outputs/session_cards/llm_session_cards_all.json
```

旧 `scripts/build_event_cards.py`、`outputs/event_cards/`、旧 schema 和旧映射文件已经归档到 `_non_mainline_archive/legacy_event_card_pipeline/` 或 `_non_mainline_archive/old_scripts/`。正式主线应新增 session card builder，按五元组、端口变化、Zeek `conn.uid`、tshark `tcp.stream`、UDP 五元组和时间窗口生成 session cards，而不是继续沿用 event-card 输出作为最终对象。

推荐未来命令形态：

```bash
python3 scripts/build_session_cards.py \
  --parsed-dir outputs/parsed \
  --output outputs/session_cards/session_cards_all.json \
  --llm-output outputs/session_cards/llm_session_cards_all.json
```

## 生成 prompt

推荐按阶段任务和技术任务分开生成 prompt，并区分 no-RAG 与 RAG：

```text
微型test_v2/outputs/prompts_qwen35_27b_stage_no_rag/
微型test_v2/outputs/prompts_qwen35_27b_stage_rag/
微型test_v2/outputs/prompts_qwen35_27b_technique_no_rag/
微型test_v2/outputs/prompts_qwen35_27b_technique_rag/
```

旧 `prompts_qwen35_27b_no_rag/`、`prompts_qwen35_27b_rag/`、`*_b2/` 已归档到 `_non_mainline_archive/old_prompts/`。正式使用前需要重新生成 session-level `stage_code` / `technique_code` prompt。

## 调用 Qwen3.5-27B

配置文件为 `configs/llm_qwen35_27b.yaml`。敏感信息只从环境变量读取，不写入仓库：

```bash
export LLM_BASE_URL="https://router.huggingface.co/v1"
export LLM_API_KEY="<set outside repo>"
export LLM_MODEL_NAME="Qwen/Qwen3.5-27B:novita"
```

fallback 模型名可使用 `Qwen/Qwen3.5-27B`，以实际服务商支持为准。不要在文档、prompt、配置或输出中写入真实 token。

现有调用脚本 `scripts/run_qwen_openai_compatible.py` 是 OpenAI-compatible runner。正式比赛运行前，应确认输入 prompt 已经是 session-level 官方编号任务，且输出不再要求 `attack_type` / `attack_stage`。

## 导出 CSV

推荐输出：

```text
outputs/submissions/stage1_submission.csv
outputs/submissions/stage2_submission.csv
outputs/submissions/submission_export_report.md
```

推荐字段以官方模板为准；在当前项目记录中统一使用：

- `stage1_submission.csv`: `pcap_id`, `session_id`, `stage_code`
- `stage2_submission.csv`: `pcap_id`, `session_id`, `technique_code`
- 人工检查报告可额外保留 `reason`, `confidence`, `evidence_refs`, `rag_doc_ids`，但这些字段不应混入正式提交模板，除非官方模板允许。

## 安全与泄露约束

- 不运行样本中的可执行文件。
- 不把测试答案、expected labels、MTA answers PDF 具体答案写入 RAG、prompt 或配置。
- 不把 API key、token、Cookie 或私密 endpoint 写入仓库。
- 不把匿名化后的 IP / 域名反推为真实实体。
- 不跨 PCAP 联合推断。
- 未取得官方 event/session-level 标签时，评估只能写 rough agreement / qualitative comparison / local validation，不写严格 accuracy。

## 当前状态和下一步

当前项目保留公开 PCAP 解析结果、RAG 知识库、chunks、keyword index、当前任务文档和 Qwen3.5-27B 环境变量配置。legacy event cards、Qwen3-14B 结果、旧 event-level Qwen3.5 prompt / partial runs、旧报告和旧脚本已经归档到 `_non_mainline_archive/`。正式比赛口径下仍需补齐：

1. sessionization / session card 生成脚本与 schema。
2. stage / technique 两阶段 prompt builder。
3. 官方编号输出解析与 CSV exporter。
4. macro-F1 / per-class F1 风格的本地验证报告模板。
5. 如需引用历史输出，先从 `_non_mainline_archive/` 中人工确认其来源和口径，只能作为 legacy qualitative comparison。

历史 Qwen3-14B 和旧 event-level JSON 实验已视为 legacy，不作为当前主线宣传。
