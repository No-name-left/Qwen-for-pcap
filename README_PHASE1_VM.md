# Phase-1 VM Runner

本分支提供从 PCAP 到本地 Qwen、Phase-1 CSV 和可选离线评估的半自动流程。推荐目录：

```text
/data/code/Qwen-for-pcap
/data/competition_input
/data/models/Qwen3.5-27B
/data/outputs/qwen_for_pcap
```

当前 Phase-1 默认行为来自稳定版本 `8b6d3bb Refine PCAP-level evidence profiles and boundary scoring`：PCAP-level candidate scoring、prompt、RAG 和推理链路保持该版本的默认行为。实验提交 `32da70c Calibrate PCAP-level benign and weak-evidence decisions` 中的 safe calibration 不作为默认行为，也不参与默认推理链路。

分支策略：`main` 是长期稳定主干，`phase1-vm-runner` 作为比赛 VM 验证/冻结分支保留到比赛结束。VM 可以继续拉取 `phase1-vm-runner`，正式回退建议优先使用稳定 tag/commit。

## 1. 检查数据盘

在堡垒机 Web 终端中先执行：

```bash
df -hT /data
findmnt /data
lsblk -f
```

只有确认数据盘设备确实是 `/dev/vdb1` 后，才手动挂载：

```bash
mkdir -p /data && mount /dev/vdb1 /data
```

脚本不会自动 mount，也不会自动下载模型或容器镜像。

## 2. 获取代码与依赖

```bash
mkdir -p /data/code
cd /data/code
git clone -b phase1-vm-runner <仓库URL> Qwen-for-pcap
cd Qwen-for-pcap
python3 -m pip install -r requirements.txt
bash scripts/check_vm_ready.sh
```

`check_vm_ready.sh` 默认不访问 API。确认本地服务已启动后，可显式检查 `/v1/models`：

```bash
bash scripts/check_vm_ready.sh --check-api \
  --base-url http://127.0.0.1:8000/v1 \
  --model qwen3.5 \
  --api-key EMPTY
```

本仓库不负责启动模型服务。OpenAI-compatible 服务应监听 `http://127.0.0.1:8000/v1`，对外模型名为 `qwen3.5`。不要把真实 key 写入仓库或命令记录；本地无需鉴权时使用 `EMPTY`。

## 3. Dry-run

Dry-run 会完成 PCAP 解析、records、RAG 和 prompts，不初始化 OpenAI client，也不伪造预测：

```bash
bash run_phase1_vm.sh \
  --input /data/competition_input/example-s3-pcaps \
  --output-dir /data/outputs/qwen_for_pcap/phase1_dryrun \
  --dry-run \
  --limit 5
```

## 4. 正式运行

不带答案表：

```bash
bash run_phase1_vm.sh \
  --input /data/competition_input/example-s3-pcaps \
  --output-dir /data/outputs/qwen_for_pcap/phase1_run \
  --base-url http://127.0.0.1:8000/v1 \
  --model qwen3.5 \
  --api-key EMPTY \
  --no-dry-run
```

带官方答案表，在推理和 CSV 导出完成后离线评估：

```bash
bash run_phase1_vm.sh \
  --input /data/competition_input/example-s3-pcaps \
  --output-dir /data/outputs/qwen_for_pcap/phase1_run \
  --base-url http://127.0.0.1:8000/v1 \
  --model qwen3.5 \
  --api-key EMPTY \
  --answer /data/competition_input/example-s3-0623/结果对照表.xlsx \
  --no-dry-run
```

省略 `--output-dir` 时，入口脚本使用 `phase1_run_<UTC时间戳>`。Web 终端中断后，使用同一个显式输出目录和 `--resume` 重跑；解析、cards、RAG、prompt 与已验证 API 结果会按基本完整性检查跳过。使用 `--no-resume` 强制重建。

配置优先级为 CLI、环境变量、`configs/phase1_vm.yaml`。可用参数还包括 `--limit`、`--rag-top-k`、`--max-prompt-tokens`、`--request-timeout` 和 `--max-retries`。

默认输出粒度是 `granularity: pcap`，也是当前 Phase-1 样例推荐模式：每个输入 PCAP 汇总为 1 条 Phase-1 记录、1 个 prompt、1 个预测，适合官方答案表按“1 PCAP -> 1 结果”对齐。底层仍会先生成 session cards、scan/auth/C2 groups 和 session/group classification records，只是这些 session/group evidence 会作为 PCAP-level 判断证据，再聚合到 `session_cards/pcap_level_records.json`。如需保留旧的逐 session/group 输出，可使用：

```bash
bash run_phase1_vm.sh \
  --input /data/competition_input/example-s3-pcaps \
  --output-dir /data/outputs/qwen_for_pcap/phase1_session_run \
  --granularity session \
  --dry-run
```

`--limit` 作用于最终输出粒度：PCAP 模式下限制 PCAP 数，session 模式下限制 session/group records 数。等价环境变量为 `PHASE1_GRANULARITY=pcap|session`。

官方提交默认输出阶段编号：

```text
TA43 / TA01 / TA03 / TA11 / TN01
```

可用以下参数控制官方导出，不影响调试 CSV：

```bash
--submission-label-level stage|technique
--pcap-id-source pcap_id|pcap_name|filename_stem
```

默认值为 `--submission-label-level stage --pcap-id-source pcap_id`。如果未来 Phase-2 需要技术编号，可改为 `--submission-label-level technique`，此时输出 `TA43_01`、`TA01_01`、`TA01_02`、`TA03_01`、`TA11_01`、`TA11_02`、`TN01_01` 等技术编号。

PCAP 模式采用：

```text
evidence profiles -> soft candidate scoring -> RAG -> LLM boundary decision
```

`scripts/technique_profiles.py` 集中维护 8 类技术画像。规则分数不是最终硬分类器，而是把 PCAP 证据压缩成 top candidates、supporting evidence、counter evidence 和 weak-evidence flags，交给 RAG 和 LLM 做边界裁决。

本地 Qwen/vLLM 默认关闭 thinking，以减少正文中出现推理文本导致 JSON 解析失败的风险。runner 发送的 OpenAI-compatible 扩展参数是：

```python
extra_body={"chat_template_kwargs": {"enable_thinking": False}}
```

默认配置为 `enable_thinking: false`，也可用 `--disable-thinking` 或 `--enable-thinking` 显式覆盖。run summary 和 `config_effective.json` 会记录：

```text
enable_thinking: false
thinking_control: chat_template_kwargs.enable_thinking
```

PCAP 解析默认按以下顺序选择解析器：

```text
system Zeek -> Docker Zeek -> TShark fallback
```

VM 默认 Docker image 为 `public.ecr.aws/zeek/zeek:8.0.6-arm64`。可用 `--zeek-docker-image` 覆盖，或用 `--no-prefer-zeek` / `--no-allow-tshark-fallback` 调整主解析策略。默认还会在 Zeek 成功后运行安全的 TShark observable supplement，只生成 `tshark/observable_http.jsonl` 这类摘要证据，用于补充 HTTP body 可见片段、可疑 URI/body 上下文和 upload hints；它不改变 `parser_source`、不生成额外 session、也不保存完整 HTTP body/raw payload/FTP 参数。可用 `--no-enable-tshark-observable-supplement` 或 `PHASE1_ENABLE_TSHARK_OBSERVABLE_SUPPLEMENT=false` 关闭。

`parse_all_summary.json`、`parse_errors.jsonl`、run summary 和 `config_effective.json` 会记录 `parser_source`、`zeek_success`、`tshark_fallback_success`、`tshark_supplement_success`、`tshark_supplement_enabled`、`payload_supplement_source`、`zeek_error` 等字段。Docker Zeek 成功时，`parser_source` 为 `zeek_docker`；若 supplement 失败，只记录 warning，Zeek 主线仍继续。

## 5. 输出

运行目录包含：

| 路径 | 内容 |
|---|---|
| `official_submission.csv` | 官方提交 CSV，严格 9 列：`pcap编号`、`开始时间`、`结束时间`、`源IP`、`源端口`、`目的IP`、`目的端口`、`攻击阶段编号或正常流量编号`、`研判理由（不计分）` |
| `official_submission.xlsx` | 如果 `openpyxl` 可用，同步生成的官方提交 Excel |
| `phase1_predictions.csv` | 调试用 UTF-8 BOM CSV，包含 `pcap_id` / `pcap_name` / `record_id` / `record_type` / `stage_code` / `technique_guess` / `confidence` / `reason`，并保留官方中文核心列；不要直接作为官方提交表 |
| `predictions.jsonl` | stage-first 结构及可选 `technique_guess` |
| `run_summary.md` / `run.log` | 汇总与逐步日志，不含 API key |
| `failed_records.jsonl` | API 或 JSON 解析失败记录 |
| `parse_errors.jsonl` | Zeek/TShark 警告和解析失败 |
| `session_cards/pcap_level_records.json` | PCAP 模式的一包一条聚合记录，包含 bounded/redacted 摘要、代表性证据、`candidate_technique_scores` / `primary_rule_candidate` / `rule_evidence` |
| `session_cards/selected_records.json` | 进入 RAG、prompt 和 API 的最终记录；随 `granularity` 切换为 PCAP 或 session/group |
| `candidate_scores.csv` | 每条最终记录的 top candidates、margin、strength、预测结果和 conflict flags |
| `candidate_score_report.md` | 候选评分与 conflict review 汇总 |
| `conflict_cases.jsonl` | 规则候选、模型输出、弱证据或正常流量反证存在冲突的记录 |
| `prompt_samples/` | 默认前 5 条 prompt 样本 |
| `prompts/prompt_manifest.json` | RAG triggers、chunks 和 prompt budget 调试信息 |
| `eval_report.md` | 提供答案表时的 Phase-1 指标 |
| `confusion_matrix.csv` / `errors.csv` / `unmatched_rows.csv` | 评估明细 |

提交用文件是 `official_submission.csv` / `official_submission.xlsx`。调试用文件包括 `phase1_predictions.csv`、`candidate_scores.csv`、`eval_report.md`、`errors.csv`、`predictions.jsonl` 和 `candidate_score_report.md`。

Prompt 使用 `observable_timing_boundary_rag_v4`，Phase-1 stage-first、technique best-effort。PCAP 模式下 prompt 会明确要求“judging whole PCAP”，展示确定性的 `candidate_technique_scores`、`top_rule_candidates`、candidate evidence/counter-evidence 和相关边界规则，并只输出整个 PCAP 的一个 `stage_code`。默认 RAG top-k 为 4，targeted boundary 优先；默认 prompt 上限为 6000 estimated tokens。超预算时先移除普通 RAG，再压缩应用摘要，最后才移除 boundary RAG，当前最终记录核心证据优先保留。

答案表只在推理结束后由评估器读取，不进入 session card、RAG query 或 prompt。评估器支持官方样例答案表列名 `攻击技术名称或正常流量`，并内置“正常流量、端口扫描、漏洞扫描、密码爆破、漏洞利用、植入后门、访问后门、木马回连”到 technique/stage 的映射。原始模型响应正文不落盘，只保存验证后的 JSON 与请求元数据。

## 6. 常见问题

- `/data` 未挂载：先运行 `df -hT /data`、`findmnt /data`、`lsblk -f`，核实设备后再手动 mount。
- API 连接失败：运行 `bash scripts/check_vm_ready.sh --check-api`，确认 `/v1/models` 和模型名；默认禁止 live 模式访问非回环地址。
- Zeek/TShark 找不到：优先安装本机 Zeek；若使用 VM 默认 Docker Zeek，确认镜像 `public.ecr.aws/zeek/zeek:8.0.6-arm64` 已存在。readiness 和 runner 不会自动 pull 镜像；Zeek 与 Docker Zeek 都失败且 `allow_tshark_fallback=true` 时才会使用 TShark fallback。Zeek 成功但 TShark supplement 失败时，主流程不会失败，只会缺少 HTTP body/payload 摘要补充并在 summary 中记录 warning。
- RAG 缺失：确认 `rag/metadata/rag_manifest.csv`、`rag/chunks/rag_chunks.jsonl`、`rag/index/keyword_index.json` 完整。
- Prompt 超预算：减小 `--rag-top-k`，或增大 `--max-prompt-tokens`，同时确保模型上下文长度足够。
- JSON 解析失败：查看 `failed_records.jsonl`，确认本地 Qwen/vLLM 接受 `chat_template_kwargs.enable_thinking=false`，修正服务模型名或输出约束后用同一目录 resume。
- 预测与答案无法对齐：查看 `unmatched_rows.csv`；评估器优先使用 `pcap+编号`，再尝试唯一编号和网络可观察字段签名。PCAP 模式下，如果某个 PCAP 在预测表和答案表中都只有一行，也会安全地按 `pcap_name` 或 `pcap_id` 对齐，不会静默丢行。若 CSV 中 `stage_code` 为空但 `technique_guess` 存在，导出和评估都会按 technique 前缀补齐 stage。
- 查看错例：先读 `eval_report.md`，再用 `errors.csv` 找错行，并用 `candidate_scores.csv` 判断是规则候选错、模型没采纳候选、证据太弱、正常流量误报还是攻击弱证据漏报。

```bash
cat <out>/eval_report.md
cat <out>/errors.csv
cat <out>/candidate_scores.csv
```

## 7. 当前边界

严格样本覆盖目前只验证了 `TA43_01`、`TA11_02`、`TN01_01`。`TA01`、`TA03`、`TA11_01`、`TA43_02` 仍需要更多高可信 PCAP 样本与真实模型运行结果。VM runner 是工程基线，不代表全类别模型质量已经通过。
