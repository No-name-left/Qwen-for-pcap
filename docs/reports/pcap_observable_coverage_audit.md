# PCAP 可见证据与时间特征覆盖审计

日期：2026-06-24

## 范围与结论

本审计覆盖 Zeek/TShark 解析、session card、classification record、RAG query、targeted RAG、最终 prompt，以及 strict/coverage 评测粒度。未下载或读取官方 `example-s3-0623`，未调用在线 API，未做 VM/Ascend/vLLM 适配。

结论：当前管线足以支持进入 VM 适配，但只适合作为 Phase-1 工程基线和已覆盖类别的回归门禁，不能声称 5 个阶段或 8 个 technique 已全面验证。`TA43_01`、`TA11_02` 和 flow-secondary `TN01_01` 有现行 strict gate；`TA01_01`、`TA43_02`、`TA01_02`、`TA03_01`、`TA11_01` 仍缺外部高可信 strict 证据。

审计发现并修复了两个与先前粒度问题同类的潜在错误：

- auth group 将每张 card 上的同端点总尝试数再次求和，可能把 10 次尝试放大为 100；现改为累加 session-local attempt count，并验证 10 次 HTTP 401 得到 `attempt_count=10`、`failed_login_count=10`。
- 通用 C2 group 曾把 1 毫秒级漏洞扫描/登录 burst 视为高 regularity beacon，并覆盖原 session；现要求多秒级 interval scale、无竞争攻击行为或有明确 callback context，且只有 `high_callback_behavioral` group 才替代 session。中/弱 group 只保留在 audit 输出。

## 实际端到端检查

使用 8 类、每类 3 个 localhost controlled PCAP 做 parser/pipeline 检查。它们只验证字段链路，绝不作为外部 strict 质量结论。

- PCAP：24；Zeek 成功 24/24；TShark 成功 24/24。
- Session cards：177；最终 records：93。
- v4 no-RAG/RAG prompts：186；最大约 3,021 estimated tokens；预算截断 0。
- Prompt 版本：`observable_timing_boundary_rag_v4`。
- RAG：108 docs、110 chunks；retrieval tests 30/30。
- 冻结 strict-v3 数据上的 v4 dry-run：smoke 4 + strict 18 prompts；最大 3,238 estimated tokens / 9,713 chars；截断 0；估算总成本 `$0.021185`；API requests 0。

| Controlled 类别 | Cards | 最终 record | 实际正向 indicator | 实际 targeted trigger | 验证性质 |
|---|---:|---|---|---|---|
| `TA43_01` | 60 | 3 scan groups | 端口 fanout / failed ratio | `scan_timing=positive` | parser/group/timing 已验证 |
| `TA43_02` | 24 | 24 sessions | vuln scan 24 | `vuln_scan_indicators=positive` | parser 已验证，group 未实现 |
| `TA01_01` | 30 | 3 auth groups | auth 30 | auth indicator + timing | group/count/failure 已验证 |
| `TA01_02` | 12 | 12 sessions | exploit 12；其中 3 有 command/access overlap | exploit/access | parser 已验证，sequence 未实现 |
| `TA03_01` | 9 | 9 sessions | implant 9 | implant | 网络侧 upload 已验证 |
| `TA11_01` | 9 | 9 sessions | backdoor access 9；implant overlap 9 | access + implant boundary | parser 已验证，group 未实现 |
| `TA11_02` | 24 | 24 sessions | C2 24，但 40 ms fixture 被正确降为 short burst | C2 + benign-periodic boundary | 负边界已验证；非 strict |
| `TN01_01` | 9 | 9 sessions | 无攻击 indicator；health path 触发正常周期边界 | benign-periodic boundary | 正常 HTTP coverage only |

## Session card 是否物尽其用

| 证据族 | Parser/session card | Record | Prompt | RAG/targeted | 审计结论 |
|---|---|---|---|---|---|
| 可见性 | `payload_visibility`、`encrypted_protocol`、`observable_payload_available`、warnings、limits | session/scan/auth/C2 保留 | observable block 展示 | encrypted card 可触发 | group 丢失 visibility 已修复 |
| HTTP | method、host、URI/full URI、status、UA、content type、body lengths | `OBSERVABLE_FIELDS` 保留 | 全部有界展示；`http_body_observed` 已补入 | Web/exploit/vuln/access cards | 完整链路 |
| Payload | command/SQLi/XSS/traversal/JNDI/base64 等有界片段 | 保留 | 脱敏、top-k、截断 | exploit mapping | 不证明执行；HTTPS 不可见 |
| 文件/上传 | Zeek files metadata、MIME、方向、multipart/upload hints | 保留 | 稀疏展示 | implant card | 不提取文件；不证明持久化 |
| 认证 | HTTP 401/403/407、Zeek SSH、Zeek/TShark FTP USER/PASS presence/530 | auth group 保留 | count/rate/interval/failure burst | auth + auth timing cards | TShark 不保存 FTP arg；SSH/HTTPS 内容仍不可见 |
| 扫描 | 端口/主机 fanout、failed ratio、URI-path fanout、404、scanner UA | scan group 或 session | duration/rate/burst + indicators | scan boundary + timing | query-value fanout误报已修复 |
| C2/beacon | endpoint、direction hint、interval、bytes、DNS/SNI、port、score | high group 可替代 session | interval/regularity/duration/benign hints | callback + benign periodic cards | burst 误聚合已修复 |
| 后门访问 | webshell path、command param、repeat endpoint、output-like hint | session 保留 | indicators 展示 | access/callback boundary | 无 access group；方向仅为网络发起方提示 |

未充分使用但本轮不作为 P0 实现的字段包括 Zeek `notice.log`/`weird.log` 的 UID 对齐摘要、TLS 证书/JA3、QUIC 深层字段和 packet-level state transition。它们属于 P2 增强，不能替代当前缺失的高可信类别样本。

## 时间特征审计

| 对象 | 审计前 | 本轮后 | 来源与进入位置 | 优先级 |
|---|---|---|---|---|
| Session | start/end/duration | 加 `packet_rate`、`byte_rate` | Zeek conn 或 TShark stream → card → record → prompt/query | P0 完成 |
| scan group | start/end/count | 加 scan duration、probe count/rate、inter-arrival、burstiness | group builder → record → timing prompt → scan timing RAG | P0 完成 |
| auth group | time span/attempt rate，但 count 可放大 | 加 first/last、session-local count、inter-attempt min/median/mean/std、failure burst | group builder → prompt/query → auth timing RAG | P0 完成 |
| C2 group | interval min/median/p90/max/CV、periodicity、beacon | 加 mean/std、regularity、fixed-endpoint duration、benign hints、竞争行为 | group builder → prompt/query → callback timing RAG | P0 完成 |
| exploit/upload/access chain | 无 | prompt/RAG 已预留字段与解释，尚无可靠 sequence builder | 需要 endpoint/time 可靠映射 | P1 未完成 |
| normal periodic | 仅普通 false-positive 卡 | 加 update/WPAD/DNS/NTP/cloud-sync 边界与 targeted hint | card/group → RAG/prompt | P1 部分完成；缺外部 PCAP |

原始 packet timestamps 不进入 prompt。只展示 start/end 身份字段以及 count、span、rate、min/median/mean/std、regularity、burstiness 和相对 delta 等紧凑摘要。小于 1 秒的摘要自适应保留 6 位；duration 为 0 时不伪造 rate。

## 加密流量

在现有外部 cards 中，scenario 1 有 30,621 条 `metadata_only`、63 条 `encrypted_tls`；scenario 6 有 5,326 条 `metadata_only`。加密或未知应用协议下仍可使用：发起方向、固定 endpoint、连接数、间隔、持续时间、包/字节模式、端口、DNS、TLS SNI 和失败状态。

限制必须同时保留：

- TLS/SSH/QUIC 隐藏 payload，不能推断命令、凭据、exploit 或 upload 内容。
- 加密不等于正常；周期性也不等于 C2。
- software update、WPAD、DNS refresh、NTP、monitoring、cloud sync、health check 和 telemetry 都可能周期化。
- endpoint ownership、主机是否受害、主机侧执行/持久化不能仅由五元组证明。

旧 strict-v3 C2 records 是在线评测时冻结的历史输入，已有 interval/beacon 但未携带 group-level visibility。本轮修复未来 group 生成路径，不改写历史在线评测记录或 prompt hash。

## 风险归因

### A. Parser/session-card 缺口

| 风险 | 状态 | 级别 |
|---|---|---|
| TShark fallback 不识别 FTP PASS/530 | 已以 command 名和 response code 修复；永不持久化 arg | P0 完成 |
| `http_body_observed` 未进入 prompt | 已修复 | P0 完成 |
| query 参数变化被当作 URI fanout | 已按 URI path 归一化 | P0 完成 |
| auth/C2 group 丢失 payload visibility | 已合并 visibility/warnings/limits | P0 完成 |
| notice/weird、TLS cert/JA3、QUIC 深层元数据未进主卡 | 保留为增强项 | P2 |

### B. Group granularity 缺口

| 风险 | 状态 | 级别 |
|---|---|---|
| auth attempt group | 已实现并修正计数/时间 | P0 完成；缺外部强样本 |
| callback group | 已实现并增加 burst/竞争行为门禁 | P0 完成 |
| vuln-scan HTTP probe group | 仅把 same-pair URI/404 context回填到 sessions | P1 |
| exploit → upload → later access sequence | 未实现；RAG/prompt 仅预留 | P1 |
| repeated backdoor access group | 未实现，只有 session indicator | P1 |
| benign periodic endpoint group | 只有 hints/边界卡，缺独立高可信 PCAP | P1 |

### C. PCAP visibility limitation

- HTTPS/SSH/QUIC 或自定义加密隐藏应用内容。
- 抓包开始/结束不覆盖完整行为链时，event order 不可证明。
- host persistence、文件落地、命令执行成功和账号攻破属于主机侧结果。
- 非标准协议、截断、snaplen、丢包和解析器未识别会留下 metadata-only。
- files metadata 或 multipart 只能证明网络侧传输迹象，不能证明恶意文件或安装成功。

## 当前评测覆盖

| Technique | 当前 strict | 其他验证 | 结论 |
|---|---:|---|---|
| `TA43_01` | 3 high-confidence PCAP scan groups | controlled timing group | 已验证，小样本 |
| `TA43_02` | 0 | 3 controlled PCAP / 24 sessions | 部分验证，缺外部 group |
| `TA01_01` | 0 | 3 controlled auth groups | parser/group 已验证，外部证据不足 |
| `TA01_02` | 0 | controlled plaintext exploit | 部分验证，缺高可信和 sequence |
| `TA03_01` | 0 | controlled upload marker | 部分验证，且 PCAP不能证明持久化 |
| `TA11_01` | 0 | controlled mock webshell access | 部分验证，缺高可信/access group |
| `TA11_02` | 3 high-confidence CTU callback groups | two CTU scenarios；controlled short-burst negative | 已验证但 family/negative diversity不足 |
| `TN01_01` | 3 flow-secondary | controlled normal HTTP | 缺高可信 benign PCAP 和周期负样本 |

Phase-1 方面，`TA43`、`TA11`、`TN01` 有门禁覆盖；`TA01`、`TA03` 尚无可靠 strict 覆盖。Phase-2 方面只有 `TA43_01`、`TA11_02`、`TN01_01` 被当前 strict gate 覆盖。

## VM gate 与部署后诊断

仍建议进入 VM 适配，理由是 parser、record、RAG、prompt、预算、安全和三个已覆盖类别已有回归门禁，本轮又消除了两个会改变记录粒度的 P0 问题。进入 VM 不等于模型质量全面通过。

部署后遇到未知 PCAP 时按以下顺序诊断：

1. 检查 `parser_source`、`payload_visibility`、`encrypted_protocol`、`extraction_warnings` 和 mapping confidence。
2. 检查决定性字段是否从 session card 保留到 record 和 `OBSERVABLE_EVIDENCE_FROM_PCAP`。
3. 检查行为是否应使用 scan/auth/C2 group，而非单 session 标签。
4. 检查 timing summary 是否足够长，短 burst 不应作为 beacon。
5. 检查 targeted triggers/cards 是否与当前证据一致，RAG 不得覆盖 record。
6. 将失败归入 parser 缺口、group 缺口或 PCAP visibility limitation，再判断是否是模型错误。

## 下一优先级

- P1：获取重复 SSH/FTP/HTTP 失败的外部 PCAP，补 `TA01_01` strict。
- P1：设计但单独评审 vuln-scan、exploit/upload/access、backdoor access group schema。
- P1：加入软件更新、WPAD、DNS/NTP、cloud sync 等真实 benign-periodic PCAP negatives。
- P1：增加独立 C2 families 和 TLS/QUIC callback captures。
- P2：按 UID 接入 notice/weird 摘要，并评估 TLS certificate/JA3/QUIC metadata 的误报收益。
