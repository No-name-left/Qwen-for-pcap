# 当前任务定义

本文档记录第二次赛前培训后，本项目采用的正式比赛任务口径。

## 1. 当前比赛任务场景

系统需要对 PCAP 中的网络会话进行安全事件识别。每一个会话对应一条判断结果。不同 PCAP 之间没有关联关系，不能跨 PCAP 联合推断。

推荐主流程：

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

## 2. 输入数据

输入为 PCAP 文件。比赛数据中的 IP 和域名可能被匿名化，但同一 PCAP 内 IP、域名、端口、协议和会话之间的关系会保留。分析时可以利用同一 PCAP 内的关联关系，但不能将一个 PCAP 的结论迁移到另一个 PCAP。

## 3. 解析工具

当前推荐使用三类离线解析工具：

- `tshark`: 提取 packet-level 字段、`tcp.stream`、协议、端口、时间、flags、长度等信息。
- `Zeek`: 使用 `conn.log`、`dns.log`、`http.log`、`ssl.log`、`notice.log`、`weird.log` 等结构化日志，重点关注 `conn.uid`。
- `Suricata`: 使用 EVE JSON / alert / flow / dns / http / tls 等输出辅助识别签名命中和异常行为。

## 4. 分析单位

当前分析单位是 session，而不是旧版 event。会话切分应重点依据：

- 五元组：源 IP、源端口、目的 IP、目的端口、协议；
- 端口变化和方向变化；
- Zeek `conn.uid`；
- tshark `tcp.stream`；
- UDP 五元组和时间窗口；
- 同一 PCAP 内的时间邻近关系。

旧 event card 可以作为 legacy 产物或迁移参考，但正式比赛应生成 session card。

## 5. PCAP 独立性

每个 PCAP 独立判断。禁止跨 PCAP 联合推断、跨 PCAP 聚合实体画像或把某个 PCAP 的攻击结论迁移到另一个 PCAP。

## 6. 第一阶段目标

第一阶段输出攻击阶段编号或正常流量编号：

| code | meaning |
| --- | --- |
| `TA43` | 侦察 |
| `TA01` | 初始访问 |
| `TA03` | 持久化 |
| `TA11` | 命令与控制 |
| `TN01` | 正常流量 / 上网及业务访问 |

推荐输出字段为 `stage_code`。

## 7. 第二阶段目标

第二阶段输出攻击技术编号或正常行为编号：

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

推荐输出字段为 `technique_code`。

## 8. 输出 CSV 字段

最终输出为 CSV，不是泛化 JSON。字段以官方模板为准；当前项目统一记录为：

- `outputs/submissions/stage1_submission.csv`: `pcap_id`, `session_id`, `stage_code`
- `outputs/submissions/stage2_submission.csv`: `pcap_id`, `session_id`, `technique_code`

研判理由不计入评分，但应保留到人工检查报告，例如：

- `outputs/submissions/submission_export_report.md`
- 可选本地审计字段：`reason`, `confidence`, `evidence_refs`, `rag_doc_ids`

这些审计字段不要加入正式提交 CSV，除非官方模板允许。

## 9. 评分方式

评分关注每个类别 F1 的平均值，应按 macro-F1 / per-class F1 的思路优化。不要只优化整体 accuracy 或 normal 占比。

在缺少真实官方 session-level 标签时，只能写：

- rough agreement
- qualitative comparison
- local validation

不要写严格 accuracy。

## 10. 当前主线模型

当前主线模型是 Qwen3.5-27B。配置通过环境变量读取：

- `LLM_BASE_URL`
- `LLM_API_KEY`
- `LLM_MODEL_NAME`

Hugging Face Router 可用配置示例：

- `LLM_BASE_URL=https://router.huggingface.co/v1`
- `LLM_MODEL_NAME=Qwen/Qwen3.5-27B:novita`
- fallback: `Qwen/Qwen3.5-27B`

不要在配置、prompt、报告或代码中写入真实 token。

## 11. RAG 作用

RAG 的作用是为 session-level 判断提供辅助知识：

- 官方标签边界；
- 攻击阶段和攻击技术解释；
- 协议、端口、工具字段解释；
- tshark / Zeek / Suricata 字段和签名解释；
- 常见误报边界；
- event/session 到 CSV 输出的辅助判断规则。

RAG 不应包含测试答案、expected labels、MTA answers PDF 具体答案、原始 PCAP 私有路径或任何密钥。

## 12. LoRA 作用

LoRA 是后续可选增强，用于学习 session-level 判别边界、输出规范和固定格式。它不是当前立即执行项，也不应在没有正式训练数据和泄露审查时启动。

## 13. Legacy 标签说明

旧枚举：

```text
normal / port_scan / exploit / backdoor / trojan_callback / c2 / other_attack
```

只作为 legacy internal semantic labels 或中间映射保留，不是最终输出类别。正式输出必须使用 `stage_code` 或 `technique_code`。
