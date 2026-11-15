# 配置说明

编辑 `cf_config.py` 调整参数。所有涉及密码/密钥的配置均支持环境变量覆盖（推荐），未设置环境变量时使用文件内默认值。

## 对接 edgetunnel（Worker 推送）

| 配置项 | 环境变量 | 默认值 | 说明 |
|--------|----------|--------|------|
| `WORKER_ENABLE` | — | `True` | 总开关，是否推送到 Worker |
| `WORKER_HOST` | `CF_WORKER_HOST` | `https://your-worker.example.com` | edgetunnel 的域名 |
| `WORKER_PASSWORD` | `CF_WORKER_PASSWORD` | `""` | edgetunnel 后台密码（对应其 `ADMIN` 变量），**必须设置** |

推送流程：`POST {WORKER_HOST}/login`（密码校验）→ `POST {WORKER_HOST}/admin/ADD.txt`（更新订阅）。

## 通知

| 配置项 | 环境变量 | 默认值 | 说明 |
|--------|----------|--------|------|
| `NOTIFY_WEBHOOK_URL` | `CF_WEBHOOK_URL` | `""` | 通用 Webhook（飞书/钉钉等） |
| `NOTIFY_TG_TOKEN` | `CF_TG_TOKEN` | `""` | Telegram Bot Token |
| `NOTIFY_TG_CHAT_ID` | `CF_TG_CHAT_ID` | `""` | Telegram 聊天 ID |

## 运行模式与源

- `RUN_MODE`: 运行模式（v4.6 为入口优选独立版，默认 `1`）
- `URL_SOURCES`: 订阅源列表（自动抓取，也可手工增删）
- `EXCLUDE_COUNTRIES` / `ONLY_COUNTRIES`: 地区过滤
- `RANDOM_SCAN_COUNT`: 每次随机扫描的 CF CIDR IP 数量
- `MAX_TASK_LIMIT`: 入口探测最大任务数

## 并发与超时

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `MAX_TCP_WORKERS` | 500 | TCP 连通性探测并发 |
| `MAX_TRACE_WORKERS` | 60 | `/cdn-cgi/trace` 并发（2026-11-11 由 100 降到 60：降并发反而减少超时） |
| `MAX_TTFB_WORKERS` | 50 | TTFB 延迟测试并发 |
| `MAX_BW_WORKERS` | 10 | 下载测速并发 |
| `TCP_TIMEOUT` | 1.0 | TCP 连接超时（秒） |
| `TRACE_TIMEOUT` | 8.0 | `/trace` 请求超时（秒；2026-11-11 由 4.0 提到 8.0，Trace 阶段曾丢掉 8.7 倍的存活节点） |
| `TRACE_RETRY` | 1 | trace 失败重试次数 |
| `TTFB_MAX` | 0.8 | TTFB 初始阈值，节点不足自动放宽 |
| `BW_MB` | 10 | 测速下载大小（MB） |
| `BW_EARLY_STOP_MBPS` | 80.0 | 达到此速度提前结束测速 |

## 订阅源抓取（2026-11-11 新增：防并发风暴）

101 个源里有 78 个同属一个域名，一次性全发 + 10s 超时在跨境链路上必然自我压垮（实测失败集合跨轮交集只有 6~22 个，单请求却 200 正常）。现在按域名分桶限流 + 失败退避：

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `FETCH_PER_HOST_LIMIT` | 8 | 同一域名最大并发数 |
| `FETCH_TOTAL_TIMEOUT` | 20.0 | 单源总超时（秒） |
| `FETCH_RETRY` | 1 | 单源失败重试次数 |
| `SOURCE_FAIL_SKIP` | 3 | 连续失败 N 轮的源本轮跳过 |
| `SOURCE_RETRY_AFTER` | 4 | 跳过后每 N 轮强制重试一次 |
| `SOURCE_HEALTH_FILE` | `Data/source_health.json` | 源健康度状态（自动维护） |
| `AUTO_UPDATE_CACHE_HOURS` | 24 | 导航站/CIDR 页缓存小时数（0 = 每次启动都爬，旧行为；实测会白占启动 13~100s） |

## IPv6 连通性检测（2026-11-11 修订）

旧版拿 CF 公共 DNS 解析器 `2606:4700:4700::1111` 做裸 TCP:443 探测——该地址不开放 443，导致 IPv6 被连续 5 轮误关（真机 `ping6` 通、`curl -6` 正常）。

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `IPV6_AUTO_DETECT` | `True` | 启动时自动检测；`False` 时直接按 `IPV6_ENABLE` 走 |
| `IPV6_ENABLE` | `True` | IPv6 扫描总开关 |
| `IPV6_TEST_HOST` | CF 边缘 v6（HKG） | 探针目标：换成真实边缘地址，或按 `IPV6_TEST_MODE="tcp"` 用裸连接 |
| `IPV6_TEST_PORT` | 443 | 探测端口 |
| `IPV6_TEST_TIMEOUT` | 5 | 检测超时（秒）；2s 在跨境抖动下会误杀 |
| `IPV6_TEST_MODE` | `"http"` | `http` = GET `/cdn-cgi/trace`（默认，最稳）；`tcp` = 裸 TCP 连接 |

## 地区分层与路由诊断（2026-11-11 新增）

把「地区基线延迟（路径成本，换 IP 改不掉）」与「节点质量（可优化）」分开：地区按基线分成 T1/T2/T3/DROP，分层只决定准入与名额，**不改 `compute_score` 的绝对口径**。

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `REGION_TIER_ENABLE` | `True` | 总开关；关闭则回到旧的「地区均分 ≥ 门槛」单条斜线判据 |
| `REGION_BASELINE_K` | 3 | 地区基线 = 该地区最好 K 个节点的 TTFB 均值 |
| `PUSH_TIER1_TTFB_MS` | 450 | T1（交互主路径）基线上限 |
| `PUSH_TIER2_TTFB_MS` | 1200 | T2 基线上限（同时要求带宽中位 ≥ `PUSH_TIER2_MIN_MBPS`） |
| `PUSH_TIER2_MIN_MBPS` | 10.0 | T2 带宽中位门槛 |
| `PUSH_TIER3_TTFB_MS` | 1600 | T3 兜底上限；超过即 DROP（本轮不推送） |
| `REGION_TIER_QUOTA_T1/T2/T3` | 4 / 3 / 1 | 每层最多贡献的地区数 |
| `PUSH_NODE_MIN_SCORE` | 20.0 | 单节点综合分下限（地区基线合格 ≠ 每个节点合格） |
| `PUSH_NODE_MIN_SCORE_KEEP` | 1 | 某地区全被剔时至少保留的节点数 |
| `ROUTE_DIAG_SEVERE` / `ROUTE_DIAG_WARN` | 20 / 10 | 基线 ÷ 物理下限（光速往返）的倍数，仅用于日志诊断 |
| `REGION_BASELINE_FILE` | `Data/region_baseline.json` | 跨轮基线快照（保留最近 8 轮） |

## 评分与推送

- `SCORE_TTFB_WEIGHT` / `SCORE_BW_WEIGHT`: 评分权重（0.6 / 0.4）
- `SCORE_MAX_TTFB_MS` / `SCORE_MAX_BPS`: 评分归一化上限（`SCORE_MAX_BPS` = 40，2026-11-11 重标定：实测天花板约 34 Mbps，原 150 让带宽项形同虚设）
- `SMART_PUSH_MIN_SCORE`: 智能推送最低评分（分层模式下由地区分层接管）
- `SMART_PUSH_MIN_NODES`: 地区至少要有几个节点才考虑
- `SMART_PUSH_MIN_NODES_FALLBACK`: 仅 1 个地区达标时，第二地区的节点门槛（输出零冗余的兜底）
- `SMART_PUSH_IPS_PER_CC`: 每地区最多贡献 IP 数
- `SMART_PUSH_MAX_TOTAL`: 最终输出最大节点总数
- `BW_TOP_N`: 测速 TOP-N 入选数
- `PUSH_MIN_MBPS`: 最终推送带宽硬下限（2.0 Mbps，0 = 关闭）；低于它的「僵尸优选」剔除后从剩余结果回填
- `PUSH_MIN_MBPS_KEEP`: 剔除后至少保留的节点数（全被剔时兜底保留最高分）
- `PUSH_MEMORY_FUSE_W_LOCAL`: 最终排序 = 本轮实测权重（0.6）+ 记忆库置信度（0.4）；填 1.0 关闭融合

## 动态调优（v4.6 新增，`cf_autotune`）

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `AUTOTUNE_ENABLE` | `True` | 总开关，`False` 全部走静态值 |
| `AUTOTUNE_EMA_ALPHA` | 0.35 | EMA 新值权重，越小越稳 |
| `AUTOTUNE_DEADZONE` | 0.12 | 相对变化小于此不写回（防抖） |
| `AUTOTUNE_HISTORY_MAX` | 20 | 保留调节历史条数 |
| `HEALTH_W_SURVIVAL` | 0.45 | 健康度-存活率权重 |
| `HEALTH_W_LATENCY` | 0.35 | 健康度-延迟权重 |
| `HEALTH_W_JITTER` | 0.20 | 健康度-抖动权重 |
| `TCP_SURVIVAL_LOW/HIGH` | 0.08 / 0.20 | 存活率低/高阈值，触发并发调整 |
| `TCP_TIMEOUT_AUTO` | `True` | 按分位数自动调节 TCP 超时 |
| `DYNAMIC_WORKERS_AUTO` | `True` | 自动调节 trace/ttfb 并发 |
| `TTFB_POOL_AUTO` | `True` | 自动调节 TTFB 候选池 |
| `TTFB_MAX_FLOOR/CEIL` | 0.70 / 2.50 | TTFB 阈值调节范围 |
| `TASK_LIMIT_MIN/MAX` | 1500 / 5000 | 任务数调节范围 |

## 评分与推送

- `SCORE_TTFB_WEIGHT` / `SCORE_BW_WEIGHT`: 评分权重（0.6 / 0.4）
- `SCORE_MAX_TTFB_MS` / `SCORE_MAX_BPS`: 评分归一化上限
- `SMART_PUSH_MIN_SCORE`: 智能推送最低评分
- `SMART_PUSH_IPS_PER_CC`: 每地区最多贡献 IP 数
- `SMART_PUSH_MAX_TOTAL`: 最终输出最大节点总数
- `BW_TOP_N`: 测速 TOP-N 入选数

## 去重与保留

- `IPV4_DEDUP_PREFIX` / `IPV6_DEDUP_PREFIX`: 网段去重粒度（v4.5 起 IPv4 默认 `/24`，IPv6 `/48`）
- `RESERVE_CAND_START/END`: 保留候选区间
- `PRIORITY_RESERVE_MIN` / `RESERVE_POOL_MIN` / `PREMIUM_SOURCE_MIN`: 各层候选池最少保留量

详情请参考 `cf_config.py` 中的代码注释。
