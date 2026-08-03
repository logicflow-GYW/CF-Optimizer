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
| `MAX_TRACE_WORKERS` | 100 | `/cdn-cgi/trace` 并发 |
| `MAX_TTFB_WORKERS` | 50 | TTFB 延迟测试并发 |
| `MAX_BW_WORKERS` | 10 | 下载测速并发 |
| `TCP_TIMEOUT` | 1.0 | TCP 连接超时（秒） |
| `TTFB_MAX` | 0.8 | TTFB 初始阈值，节点不足自动放宽 |
| `BW_MB` | 10 | 测速下载大小（MB） |
| `BW_EARLY_STOP_MBPS` | 80.0 | 达到此速度提前结束测速 |

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
