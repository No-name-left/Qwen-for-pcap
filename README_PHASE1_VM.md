# Phase-1 VM Runner

本分支提供从 PCAP 到本地 Qwen、Phase-1 CSV 和可选离线评估的半自动流程。推荐目录：

```text
/data/code/Qwen-for-pcap
/data/competition_input
/data/models/Qwen3.5-27B
/data/outputs/qwen_for_pcap
```

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

## 5. 输出

运行目录包含：

| 路径 | 内容 |
|---|---|
| `phase1_predictions.csv` | UTF-8 BOM、官方 Phase-1 列顺序，最终只含 stage label |
| `predictions.jsonl` | stage-first 结构及可选 `technique_guess` |
| `run_summary.md` / `run.log` | 汇总与逐步日志，不含 API key |
| `failed_records.jsonl` | API 或 JSON 解析失败记录 |
| `parse_errors.jsonl` | Zeek/TShark 警告和解析失败 |
| `prompt_samples/` | 默认前 5 条 prompt 样本 |
| `prompts/prompt_manifest.json` | RAG triggers、chunks 和 prompt budget 调试信息 |
| `eval_report.md` | 提供答案表时的 Phase-1 指标 |
| `confusion_matrix.csv` / `errors.csv` / `unmatched_rows.csv` | 评估明细 |

Prompt 使用 `observable_timing_boundary_rag_v4`，Phase-1 stage-first、technique best-effort。默认 RAG top-k 为 4，targeted boundary 优先；默认 prompt 上限为 6000 estimated tokens。超预算时先移除普通 RAG，再压缩应用摘要，最后才移除 boundary RAG，当前 session/group 核心证据优先保留。

答案表只在推理结束后由评估器读取，不进入 session card、RAG query 或 prompt。原始模型响应正文不落盘，只保存验证后的 JSON 与请求元数据。

## 6. 常见问题

- `/data` 未挂载：先运行 `df -hT /data`、`findmnt /data`、`lsblk -f`，核实设备后再手动 mount。
- API 连接失败：运行 `bash scripts/check_vm_ready.sh --check-api`，确认 `/v1/models` 和模型名；默认禁止 live 模式访问非回环地址。
- Zeek/TShark 找不到：安装本机命令；readiness 只识别已经存在的 Zeek Docker image，不会自动 pull。
- RAG 缺失：确认 `rag/metadata/rag_manifest.csv`、`rag/chunks/rag_chunks.jsonl`、`rag/index/keyword_index.json` 完整。
- Prompt 超预算：减小 `--rag-top-k`，或增大 `--max-prompt-tokens`，同时确保模型上下文长度足够。
- JSON 解析失败：查看 `failed_records.jsonl`，修正服务模型名或输出约束后用同一目录 resume。
- 预测与答案无法对齐：查看 `unmatched_rows.csv`；评估器优先使用 `pcap+编号`，再尝试唯一编号和网络可观察字段签名，不会静默丢行。

## 7. 当前边界

严格样本覆盖目前只验证了 `TA43_01`、`TA11_02`、`TN01_01`。`TA01`、`TA03`、`TA11_01`、`TA43_02` 仍需要更多高可信 PCAP 样本与真实模型运行结果。VM runner 是工程基线，不代表全类别模型质量已经通过。
