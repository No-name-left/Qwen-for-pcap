# Zeek/TShark 与 session-card 按阶段/技术覆盖索引

本文件是 `pcap_observable_coverage_audit.md` 的按类索引。状态含义：已验证表示有真实外部 strict；部分验证表示只有 controlled/局部链路；证据不足表示当前数据不能支持高可信结论。

## Phase-1 阶段摘要

| 阶段 | 理想网络证据 | Zeek 稳定字段 | TShark 补充 | 当前链路/测试 | 风险与状态 |
|---|---|---|---|---|---|
| `TA43` 侦察 | port/host fanout、失败、service/URI probe、burst | conn state/bytes/service/http | flags、stream timing、HTTP URI/UA | scan group 全链；strict 仅 `TA43_01` | 中；部分验证 |
| `TA01` 初始访问 | auth failures 或 exploit request/response | HTTP/FTP/SSH metadata、files | bounded HTTP body/form、FTP command/code | controlled auth/exploit 全链；strict 0 | 高；证据不足 |
| `TA03` 持久化 | upload/delivery/implant placement | HTTP/files metadata | multipart/body/file-name context | controlled upload；无 sequence/strict | 高；部分验证，主机成功不可见 |
| `TA11` C2 | backdoor access 或 victim callback/beacon | conn/DNS/TLS/HTTP | timing/size/SNI/HTTP | strict callback 3；access 仅 controlled | 中；部分验证 |
| `TN01` 正常 | benign Web/DNS/TLS/update/periodic | all ordinary protocol metadata | timing/SNI/HTTP | strict 3 flow-secondary；controlled HTTP | 中；缺 PCAP 周期负样本 |

## `TA43_01` 端口扫描

1. 理想证据：多端口/多主机、短连接、高失败比、SYN fanout、probe burst。
2. Zeek：`conn.log` 的 endpoint、port、state、duration、bytes、history。
3. TShark：TCP flags、stream、frame time/len，Zeek 缺失时可回退。
4. Group：必须；同 PCAP/source/destination/protocol/time window 聚合。
5. 加密限制：不影响 fanout 判断；看不到加密应用 probe 内容。
6. Session card：已有 fanout、failed rate、start/end/rates。
7. Record：scan group 保留 count、ports、duration、probe rate、inter-arrival、burstiness。
8. Prompt：v4 timing/observable block 展示紧凑摘要。
9. RAG：port scan 与 vuln scan 边界、scan timing card。
10. Trigger：`scan_timing=positive` 和 scan confusion boundary。
11. 测试：3 strict high PCAP；3 controlled timing groups。
12. 粒度风险：已通过 group 解决；冻结 strict-v3 scan records 尚无新 rate 字段。
13. 风险：低。
14. 状态：已验证，小样本。

## `TA43_02` 漏洞扫描

1. 理想证据：scanner UA、service/version probe、CVE/path、URI-path fanout、404 pattern。
2. Zeek：HTTP method/host/URI/status/UA 与 conn context。
3. TShark：full URI、headers metadata、bounded body/probe string、packet timing。
4. Group：跨多个 HTTP sessions 时建议 vuln-scan group；当前只回填 same-pair context。
5. 加密限制：HTTPS 下 scanner path/body 不可见，只剩 endpoint/timing/SNI。
6. Session card：已有 scanner、probe path、normalized URI fanout、404 rate。
7. Record：session 保留 indicators；无专用 group。
8. Prompt：indicator、URI/UA、rates 可展示。
9. RAG：vuln scan card及 `TA43_01/TA43_02` 边界。
10. Trigger：`vuln_scan_indicators=positive`。
11. 测试：3 controlled PCAP / 24 sessions；strict 0。
12. 粒度风险：中，多 session scanner campaign 可能被逐 session 评估。
13. 风险：中。
14. 状态：部分验证。

## `TA01_01` 密码爆破

1. 理想证据：同 endpoint 重复认证、401/403/407、FTP 430/530、SSH failure、失败后成功。
2. Zeek：HTTP、FTP USER/PASS presence/reply、SSH auth attempts/success。
3. TShark：HTTP bounded fields；fallback 安全提取 FTP command/code，不提取 arg。
4. Group：必须；same PCAP/src/dst/port/protocol/close window。
5. 加密限制：SSH/HTTPS 凭据与响应内容隐藏；无 failure signal 时只能 weak。
6. Session card：有 session-local attempts、failure count、protocol、safe presence。
7. Record：有 count/span/rate/inter-arrival/failure burst/visibility。
8. Prompt：全部紧凑展示，不含用户名/密码值。
9. RAG：auth boundary + auth timing card。
10. Trigger：auth indicator + `auth_timing=positive`。
11. 测试：3 controlled HTTP 401 groups；FTP fallback unit；strict 0。
12. 粒度风险：计数放大已修；外部数据仍缺 endpoint/application fields。
13. 风险：高。
14. 状态：parser/group 已验证，标签证据不足。

## `TA01_02` 漏洞利用

1. 理想证据：exploit URI/body/parameter、SQLi/command/traversal/XSS/CVE 触发及 response context。
2. Zeek：HTTP metadata、files、service/conn；明文 body能力有限。
3. TShark：bounded/redacted body/form/full URI，是主要补充。
4. Group：单请求可判断 attempt；scan→exploit sequence 是 P1。
5. 加密限制：HTTPS payload 不可见，不能从 timing 单独断言 exploit。
6. Session card：主要 payload patterns 已覆盖，包括 JNDI/base64 hints。
7. Record：完整保留 snippets/params/indicators。
8. Prompt：有界 top-k 展示，cookie/auth 仅 presence。
9. RAG：exploit mapping、normal boundary、access boundary。
10. Trigger：`exploit_indicators=positive`。
11. 测试：controlled plaintext 12 sessions；strict 0。
12. 粒度风险：scanner probe 与 exploit、later access 易混；sequence 未实现。
13. 风险：高。
14. 状态：部分验证。

## `TA03_01` 植入后门

1. 理想证据：server-directed upload、multipart、script/executable/archive、download/dropper chain。
2. Zeek：HTTP/files filename/MIME/direction/size metadata。
3. TShark：upload URI、multipart/content type、bounded body context。
4. Group：exploit→upload→later access chain 建议 P1 sequence group。
5. 加密限制：HTTPS upload 内容不可见；PCAP不能证明文件落地或持久化成功。
6. Session card：upload/file/implant indicators 已有。
7. Record：保留 file summary 与网络侧 limitation。
8. Prompt：明确只能判断 upload/delivery 迹象。
9. RAG：file upload/implant card + event-sequence card。
10. Trigger：`implant_indicators=positive`；sequence 字段未来触发。
11. 测试：3 controlled upload PCAP / 9 sessions；strict 0。
12. 粒度风险：高，单 upload 也可能是正常业务；完整 chain 未实现。
13. 风险：高。
14. 状态：部分验证；持久化结果不可见。

## `TA11_01` 访问后门

1. 理想证据：已有 webshell/control endpoint、command param、重复访问、output-like response、attacker-initiated role。
2. Zeek：HTTP URI/method/status/files 与 conn originator。
3. TShark：full URI、bounded command context、response snippet/timing。
4. Group：重复 endpoint/command interval 的 backdoor-access group 尚未实现。
5. 加密限制：HTTPS/SSH interactive commands 不可见；endpoint ownership 不可证明。
6. Session card：webshell path、command param、repeat endpoint、output hint 已有。
7. Record：session 保留；无专用 group。
8. Prompt：direction/indicator 展示并与 callback 区分。
9. RAG：access-vs-callback、exploit-vs-access、event sequence。
10. Trigger：`backdoor_access_indicators=positive`。
11. 测试：3 controlled mock-webshell PCAP / 9 sessions；strict 0。
12. 粒度风险：高，first injection、upload 和 later access 易混。
13. 风险：高。
14. 状态：部分验证。

## `TA11_02` 木马回连

1. 理想证据：source-initiated fixed endpoint、multi-second intervals、similar sizes、DNS/SNI repetition、unusual port/context。
2. Zeek：conn/DNS/TLS/HTTP/service/duration/bytes。
3. TShark：stream timing、frame size、SNI/HTTP；适合加密 metadata。
4. Group：必须；同 endpoint 连接序列。
5. 加密限制：payload/C2 command不可见；metadata可支持但不能证明 malware family。
6. Session card：interval mean/median/std/CV、regularity、duration、benign hints。
7. Record：high group保留 visibility、direction、interval/bytes/DNS/SNI/score。
8. Prompt：timing block 与 encrypted limitation 均展示。
9. RAG：callback/access、callback/normal、beacon/benign periodic cards。
10. Trigger：C2、callback timing、encrypted timing、benign periodic（按证据）。
11. 测试：3 strict CTU groups，两个 scenario；controlled 40 ms burst 被正确降级。
12. 粒度风险：扫描/auth burst误聚合已修；family与正常负样本仍少。
13. 风险：中。
14. 状态：已验证但覆盖有限。

## `TN01_01` 上网及业务访问

1. 理想证据：普通 Web/DNS/TLS、更新、遥测、NTP、WPAD、cloud sync、无决定性攻击行为。
2. Zeek：完整常见协议 metadata、conn state/bytes/duration。
3. TShark：packet/stream timing、SNI、HTTP，Zeek fallback。
4. Group：周期性正常 endpoint 建议独立 negative group；当前无高可信 group。
5. 加密限制：缺 payload 不自动等于正常；必须保守使用 metadata。
6. Session card：normal flow features、rates、benign periodic hints。
7. Record：保留；现 strict 是 flow-secondary。
8. Prompt：明确 periodic/encrypted 都不能自动判恶意或正常。
9. RAG：normal boundary、encrypted limits、normal periodic boundary。
10. Trigger：普通 outbound confusion；有真实 benign hint 时定向触发。
11. 测试：3 strict flow-secondary；3 controlled normal HTTP；无外部周期 PCAP。
12. 粒度风险：高频 update/DNS/telemetry 可被误判 C2，需更多 negative。
13. 风险：中。
14. 状态：部分验证。

## 不阻塞 VM 但必须保留的边界

- Phase-1 未可靠 strict 覆盖 `TA01` 和 `TA03`。
- Phase-2 未可靠 strict 覆盖 `TA43_02`、`TA01_01`、`TA01_02`、`TA03_01`、`TA11_01`。
- PCAP 无法证明 host-side persistence、execution、file installation 或 account compromise。
- 大型 sequence group 需单独设计、评审和测试，本轮仅加入字段/RAG契约，不实现自动合并。
