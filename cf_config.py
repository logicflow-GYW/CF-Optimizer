# ============================================================
#  CF Optimizer v4.5 — 配置文件 (第二轮结构优化版)
#  v4.4 改动：第一轮最小修复（8个关键bug）
#  v4.5 改动：第二轮结构优化（统一节点模型、优先级保留、IPv6检测）
# ============================================================
import os
import urllib.request
import re
import json
import time

# ────────────────────────────────────────────────
#  运行模式
#  1 = 仅入口 IP 测速
#  2 = 仅代理 IP 纯净度检测
#  3 = 两者都运行
# ────────────────────────────────────────────────
RUN_MODE = 1

# ────────────────────────────────────────────────
#  日志详细程度开关
#  True = 开启调试模式，日志文件会记录所有底层网络报错（推荐排障时使用）
#  False = 仅记录核心流程
# ────────────────────────────────────────────────
DEBUG_MODE = False

# ────────────────────────────────────────────────
#  IP 来源与分类配置 (极简纯净版)
# ────────────────────────────────────────────────
URL_SOURCES = [
    # 核心巨无霸稳定源 (包含约 15000+ IP)
    # 策略：不一次性全扫，利用 sample_limit 每次随机抽取 3000 个，保证每次测的 IP 不重样，且不撑爆内存
    {"url": "https://zip.cm.edu.kg/all.txt", "type": "txt", "quality": "bulk", "sample_limit": 3000},

]

# ────────────────────────────────────────────────
#  国家/地区过滤
# ────────────────────────────────────────────────
# 黑名单：入口/代理探测时排除的国家/地区（即使在白名单也会被这里拦截）
EXCLUDE_COUNTRIES = {
    "RU", "KP", "CN", "HK"
}

# 白名单：只保留以下国家/地区（2 位 ISO 代码）
# 用法 1：只挑选特定国家，例如 {"SG", "US"}
# 用法 2：如果想恢复原有逻辑（全网盲测），只需将大括号留空，写成 set() 即可！
ONLY_COUNTRIES = set() #{"SG"}

# 代理 IP 写入 Worker 时优先排在前面的国家
PROXYIP_PREFER_COUNTRIES = ["SG", "TW", "US"]

# Worker config.json 里最多写入多少个代理 IP
PROXYIP_COUNT = 5

# ────────────────────────────────────────────────
#  并发 & 超时
# ────────────────────────────────────────────────
MAX_TASK_LIMIT       = 5000   # 入口探测最大任务数（shuffle 后截断）
RANDOM_SCAN_COUNT    = 15000  # 每次随机扫描的 CF CIDR IP 数量（从网段中抽盲盒的数量）

MAX_TCP_WORKERS      = 500    # TCP 连通性探测并发数
MAX_TRACE_WORKERS    = 60     # /cdn-cgi/trace 并发数（2026-11-11: 100→60，降并发反而减少超时）
MAX_API_WORKERS      = 20     # 代理能力 API 验证并发数
MAX_TTFB_WORKERS     = 50     # TTFB 延迟测试并发数
MAX_BW_WORKERS       = 10     # 下载测速并发数
MAX_PURITY_WORKERS   = 2      # ip-api.com 纯净度检测并发数

# TCP 并发控制上下限
TCP_WORKERS_MIN_CAP  = 100    # TCP 并发最小值
TCP_WORKERS_MAX_CAP  = 500    # TCP 并发最大值（与 MAX_TCP_WORKERS 保持一致）

TCP_TIMEOUT          = 1.0    # TCP 连接超时（秒）
# TRACE_TIMEOUT 的权威定义在下方「Trace / TTFB 并发随健康度联动」段（8.0s），此处不再重复定义
TTFB_MAX             = 0.8    # 初始 TTFB 目标阈值，节点不足时会自动放宽
BW_MB                = 10     # 测速下载大小（MB）
BW_TIMEOUT           = 15.0   # 测速超时（秒）
BW_EARLY_STOP_MBPS   = 80.0   # 达到此速度后提前结束测速（Mbps）

# ────────────────────────────────────────────────
#  流水线内部限制
# ────────────────────────────────────────────────
TCP_ALIVE_LIMIT      = 2500
TCP_ALIVE_LIMIT_MIN  = 1000
TCP_ALIVE_LIMIT_MAX  = 4000
# 2026-11-11 新增：TCP_ALIVE_LIMIT 截断时分层保留，避免把记忆库/备用池好节点随机切掉
TCP_ALIVE_KEEP_PRIORITY = True
TTFB_POOL_LIMIT      = 120
PROXY_API_LIMIT      = 300
PROXY_PURITY_LIMIT   = 100
BW_TOP_N             = 4
RESERVE_CAND_START   = 20
RESERVE_CAND_END     = 120
RESERVE_MAX          = 1500
PREMIUM_MAX          = 50
IPAPI_MIN_INTERVAL   = 1.4

# ────────────────────────────────────────────────
#  Range 请求检测 (下载器兼容性)
#  True  = 开启检测（适合用于 Aria2/IDM 断点续传场景）
#  False = 关闭（推荐：入口 IP 优选不需要这个检测，会大幅淘汰节点）
# ────────────────────────────────────────────────
RANGE_CHECK_ENABLE = False  # ← 默认关闭，关键修复
RANGE_CHECK_HOST   = "speed.cloudflare.com"  # ← 用稳定的 speed 域名代替 cdnjs

# ────────────────────────────────────────────────
#  Worker 推送与消息通知 (可选)
# ────────────────────────────────────────────────
WORKER_ENABLE   = True
# ⚠️ 请填你自己的 edgetunnel 域名与 ADMIN 密码，或改用环境变量（推荐：避免把凭据写进文件）
WORKER_HOST     = os.environ.get("CF_WORKER_HOST", "https://your-worker.example.com")
WORKER_PASSWORD = os.environ.get("CF_WORKER_PASSWORD", "")

NOTIFY_WEBHOOK_URL = os.environ.get("CF_WEBHOOK_URL", "")
NOTIFY_TG_TOKEN   = os.environ.get("CF_TG_TOKEN", "")
NOTIFY_TG_CHAT_ID = os.environ.get("CF_TG_CHAT_ID", "")

# ────────────────────────────────────────────────
#  输出文件过期时间
# ────────────────────────────────────────────────
OUTPUT_TTL_DAYS = 14  # 多网络合并时，超过此天数的输出文件不参与合并（2026-11-11: 7→14，保住跨网络兜底）

# ────────────────────────────────────────────────
#  订阅源抓取（2026-11-11 新增：防并发风暴）
#  101 个 URL 里 78 个同属 bestcf.pages.dev，一次性全发 + 10s 超时
#  在跨境链路上必然自我压垮（失败集跨轮交集仅 6~22，单请求 200 正常）
# ────────────────────────────────────────────────
FETCH_PER_HOST_LIMIT   = 8      # 同一域名最大并发数
FETCH_TOTAL_TIMEOUT    = 20.0   # 单源总超时（秒）
FETCH_RETRY            = 1      # 失败重试次数
SOURCE_HEALTH_FILE     = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Data", "source_health.json")
SOURCE_FAIL_SKIP       = 3      # 连续失败 N 轮后跳过该源
SOURCE_RETRY_AFTER     = 4      # 跳过后第 N 轮强制重试一次

# 动态通讯录（导航站/CIDR 爬虫）缓存小时数；0 = 每次启动都爬（旧行为）
AUTO_UPDATE_CACHE_HOURS = 24

# ────────────────────────────────────────────────
#  HTTP 请求头
# ────────────────────────────────────────────────
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

# ────────────────────────────────────────────────
#  Cloudflare 端口与内置静态 CIDR
# ────────────────────────────────────────────────
CF_HTTPS_PORTS = {443, 8443, 2053, 2096, 2087, 2083}
CF_HTTP_PORTS  = {80, 8080, 8880, 2052, 2082, 2086, 2095}
CF_PORTS       = CF_HTTPS_PORTS | CF_HTTP_PORTS

# 官方内置 IPv4 网段库 (后续会被自动化爬虫扩充)
CF_CIDR_LIST = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]

# 官方内置 IPv6 网段库 (后续会被自动化爬虫扩充)
CF_IPV6_CIDR_LIST = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]

# 是否启用 IPv6（需要运行环境有 IPv6 出口）
IPV6_ENABLE = True

# ────────────────────────────────────────────────
#  智能多地区推送阈值
# ────────────────────────────────────────────────
SMART_PUSH_MIN_SCORE  = 30.0   # 地区平均评分下限（0~100），低于此不推
SMART_PUSH_MIN_NODES  = 3      # 地区至少要有几个节点才考虑
SMART_PUSH_IPS_PER_CC = 4      # 每个入选地区最多贡献几个 IP
SMART_PUSH_MAX_TOTAL  = 12     # 智能推送模式下最终输出的最大节点总数

# ────────────────────────────────────────────────
#  第二轮优化新增配置
# ────────────────────────────────────────────────
# 网段去重粒度
IPV4_DEDUP_PREFIX = 24  # IPv4 按 /24 去重（前3段）
IPV6_DEDUP_PREFIX = 48  # IPv6 按 /48 去重

# 候选任务优先级保留
PRIORITY_RESERVE_MIN  = 50   # 优先候选至少保留数量
RESERVE_POOL_MIN      = 100  # 备用池至少保留数量
PREMIUM_SOURCE_MIN    = 200  # premium 源至少保留数量

# IPv6 连通性检测
IPV6_AUTO_DETECT = True  # 启动时自动检测 IPv6 连通性
# 检测探针必须是"真实边缘"，不能用公共 DNS 解析器（2606:4700:4700::1111 对 TCP:443 不可达，
# 曾导致 v6 全量误关 5 轮，2026-11-11 诊断）。此处用 CF 边缘 v6（HKG，2403:18c0:4::/48）。
IPV6_TEST_HOST   = "2403:18c0:4:5fd:be24:11ff:fe74:78ba"  # CF 边缘 IPv6（HKG）
IPV6_TEST_PORT   = 443
IPV6_TEST_TIMEOUT = 5      # 检测超时（秒），2s 在跨境抖动时误杀
# 检测协议："http" = GET /cdn-cgi/trace（推荐，验证应用层）, "tcp" = 裸 TCP 连接
IPV6_TEST_MODE    = "http"
# 检测失败后是否彻底关闭 IPv6：False = 仅本轮跳过 v6 盲扫，仍尝试源里的 v6 条目
IPV6_DISABLE_ON_FAIL = True

# ================================================
#  自动调优 (Auto-Tuning) 统一配置  [v4.6 新增]
# ================================================
AUTOTUNE_ENABLE        = True    # 总开关，False 全走静态值
AUTOTUNE_EMA_ALPHA     = 0.35    # EMA 新值权重，越小越稳
AUTOTUNE_DEADZONE      = 0.12    # 相对变化小于此不写回，防抖
AUTOTUNE_HISTORY_MAX   = 20      # 保留最近多少条调节历史

# — 网络健康度权重（存活/延迟/抖动）——
HEALTH_W_SURVIVAL      = 0.45
HEALTH_W_LATENCY       = 0.35
HEALTH_W_JITTER        = 0.20

# — TCP 存活率阈值（替换硬编码 0.08 / 0.20 / 30）——
TCP_SURVIVAL_LOW       = 0.08
TCP_SURVIVAL_HIGH      = 0.20
TCP_WORKERS_STEP       = 30

# — TCP 超时自适应（新增）——
TCP_TIMEOUT_AUTO       = True
TCP_TIMEOUT_MIN        = 0.6
TCP_TIMEOUT_MAX        = 2.0
TCP_TIMEOUT_PCTL       = 0.95
TCP_TIMEOUT_FACTOR     = 2.0

# — Trace / TTFB 并发随健康度联动（新增）——
DYNAMIC_WORKERS_AUTO   = True
TRACE_WORKERS_MIN      = 50
TRACE_WORKERS_MAX      = 150
TRACE_TIMEOUT          = 8.0    # 2026-11-11: 4→8，Trace 阶段曾丢 8.7 倍节点（TCP 存活 2481~4533 → 有效仅 135~1173）
TRACE_RETRY            = 1      # trace 失败重试次数
TTFB_WORKERS_MIN       = 25
TTFB_WORKERS_MAX       = 80

# — TTFB 池闸门自适应（新增，替换固定 80）——
TTFB_POOL_AUTO         = True
TTFB_POOL_MIN          = 50
TTFB_POOL_MAX          = 120

# — TTFB_MAX 升降边界（替换硬编码 0.7 / 2.5）——
TTFB_MAX_FLOOR         = 0.70
TTFB_MAX_CEIL          = 2.50

# — 任务量趋势阈值（替换硬编码 0.18 / 0.25 / 1500 / 5000）——
TASK_LIMIT_MIN         = 2000
TASK_LIMIT_MAX         = 8000
TTFB_TOP10_GOOD_MS     = 180     # Top10 均延迟低于此算"过剩"
TTFB_TOP10_POOR_MS     = 250     # 高于此算"头部欠佳"
TASK_LIMIT_TREND_N     = 2       # 连续 N 轮同向才动 MAX_TASK_LIMIT

# — jitter 阈值（配置化 + 保守放宽）——
TTFB_JITTER_LIMIT      = 0.20
TTFB_JITTER_MAX        = 0.25    # 过关率过低时最多放宽到此

# — 评分常量（收敛原散落的 800 / 150 / 0.6 / 0.4）——
SCORE_TTFB_WEIGHT      = 0.6
SCORE_BW_WEIGHT        = 0.4
SCORE_MAX_TTFB_MS      = 800.0
SCORE_MAX_BPS          = 40.0   # 2026-11-11 重标定：实测天花板 ~34Mbps，原 150 使带宽项形同虚设（推送过 0.9Mbps 节点）

# ── 推送硬下限与冗余（2026-11-11 新增）——
PUSH_MIN_MBPS          = 2.0    # 最终推送节点带宽下限（Mbps），低于此剔除；0=关闭
PUSH_MIN_MBPS_KEEP     = 1      # 剔除后至少保留的节点数（全都被剔时兜底回填最高分）
SMART_PUSH_MIN_NODES_FALLBACK = 2  # 仅 1 个地区达标时，第二地区门槛降到此节点数

# ── 最终推送与记忆库融合（2026-11-11 新增）──
# 最终排序分 = w_local × 本轮实测分 + w_memory × 记忆库置信度（avg_score，经衰减）
# 目的：抗单轮 5s 采样方差（实证：43.165.135.8 跨轮 [0.9, 1.0, 31.5, 0.9] Mbps）
PUSH_MEMORY_FUSE_W_LOCAL  = 0.6   # 本轮实测权重（1.0 = 关闭融合，纯本轮分）

# ── 地区分层与路由诊断（2026-11-11 新增）──
# 把「地区基线延迟（路径成本，换 IP 改不掉）」与「节点质量（可优化）」分开。
# 依据：8 个地区「物理下限 vs 实测最优」相关系数 r=0.21 —— 延迟由国际出口路由决定，不是距离。
# 分层只用于推送准入 + 诊断日志，不改 compute_score 的绝对口径（相对分会把 1103ms 排到 599ms 前面）。
REGION_TIER_ENABLE       = True
REGION_BASELINE_K        = 3      # 地区基线 = 该地区最好 K 个节点的 TTFB 均值
PUSH_TIER1_TTFB_MS       = 450    # T1 交互主路径：基线 <= 此值
PUSH_TIER2_TTFB_MS       = 1200   # T2 大流量：基线 <= 此值 且 带宽中位 >= PUSH_TIER2_MIN_MBPS
PUSH_TIER2_MIN_MBPS      = 10.0
PUSH_TIER3_TTFB_MS       = 1600   # T3 兜底：基线 <= 此值；超过 -> DROP
REGION_TIER_QUOTA_T1     = 4      # 每层最多贡献的地区数
# 单节点准入：地区基线只决定「这个地区值不值得推」，节点本身还要过绝对分门槛。
# 否则 991ms/8.3Mbps 的节点会借着 DE 基线合格混进来（2026-11-11 实测）。
PUSH_NODE_MIN_SCORE      = 20.0   # 单节点综合分下限（0~100）；低于此不提
PUSH_NODE_MIN_SCORE_KEEP = 1      # 某地区全被剔时至少保留的节点数

REGION_TIER_QUOTA_T2     = 3
REGION_TIER_QUOTA_T3     = 1
# 路由诊断：基线 / 物理下限（光在光纤 ~2e8 m/s 往返）
ROUTE_DIAG_SEVERE        = 20.0   # >20x 严重绕路（换 IP 有救）
ROUTE_DIAG_WARN          = 10.0   # 10~20x 偏绕路
# 参考点（中国大陆）到各 ISO 地区的大圆单程距离 km，仅用于诊断，不参与评分
REGION_DISTANCE_KM = {
    "JP": 2000, "KR": 900, "SG": 3800, "TW": 1700, "HK": 1900, "MO": 1900,
    "IN": 4500, "US": 10500, "CA": 10500, "DE": 8800, "FR": 9200, "NL": 8900,
    "GB": 9200, "IE": 9500, "BE": 9000, "CH": 8500, "AT": 7900, "IT": 8200,
    "ES": 9400, "PL": 7300, "CZ": 7600, "SK": 7500, "HU": 7800, "BY": 7000,
    "LT": 6900, "LV": 6800, "EE": 6600, "FI": 7000, "SE": 7500, "DK": 7400,
    "IS": 8400, "BG": 7700, "TR": 6800, "AU": 8000, "MY": 3300, "ID": 4500,
    "TH": 2800, "VN": 2300, "AE": 6400,
}
REGION_BASELINE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Data", "region_baseline.json")

# — PID 负反馈控制器参数（v4.7 修复死亡螺旋）——
# 注意：CIDR 盲扫天然丢包率高达 75-90%，这是正常的，不是"网络过载"
PID_LOSS_RATE_TARGET      = 0.85   # TCP 目标丢包率（0.85=容忍85%丢包，盲扫常态，v4.7 修正）
PID_HIGH_FAIL_TARGET      = 0.50   # Trace/TTFB 高层失败率容忍阈值（0.50=容忍50%失败，v4.7 修正）
PID_CONCURRENCY_DOWN_GAIN = 0.8    # 并发度下调增益（丢包超标时，越小越保守）
PID_CONCURRENCY_UP_GAIN   = 1.0    # 并发度上调增益（网络良好时，越大恢复越快）
PID_ALIVE_DOWN_GAIN       = 0.8    # 存活上限下调增益
PID_ALIVE_UP_GAIN         = 1.2    # 存活上限上调增益（偏大以加速恢复）
PID_INTEGRAL_DECAY        = 0.5    # 跨轮次积分衰减系数（防历史累积导致死锁）
PID_INTEGRAL_MAX          = 0.5    # 积分器饱和上限（原 2.0 太大导致积分风暴）

# — 均值回归（防止参数无限漂移）——
# 建议取值：0.05 ~ 0.20。0.10 表示每轮自动回拉差距的 10% 逼近默认配置。
MEAN_REVERSION_STRENGTH   = 0.10   # 每轮向配置默认值回拉比例（0=不回拉, 1=每轮重置）


# ================================================
#  自动调优 (Auto-Tuning) 统一配置  [v4.6 新增]
# ============================================================
#  自动化网络爬虫模块：全自动获取最新源 (通讯录模式)
# ============================================================
def fetch_text_lines(url):
    """辅助函数：请求网址并按行返回文本，自带异常处理"""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
        content = urllib.request.urlopen(req, timeout=10).read().decode('utf-8')
        return content.splitlines()
    except Exception:
        return []

def auto_update_config():
    global URL_SOURCES, CF_CIDR_LIST, CF_IPV6_CIDR_LIST
    print("\n" + "=" * 54)
    print("启动动态通讯录：全自动获取最新订阅源链接...")

    # 自动创建 Data 目录并存放通讯录缓存
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Data")
    os.makedirs(data_dir, exist_ok=True)
    url_cache_file = os.path.join(data_dir, "latest_urls.txt")

    # ── 24h 缓存闸门（2026-11-11）：导航站 + CIDR 页同步串行爬曾白占启动 13~100s
    cache_hours = float(globals().get("AUTO_UPDATE_CACHE_HOURS", 0) or 0)
    cache_meta = os.path.join(data_dir, "latest_urls.meta.json")
    if cache_hours > 0 and os.path.exists(url_cache_file) and os.path.exists(cache_meta):
        try:
            with open(cache_meta, encoding="utf-8") as f:
                meta = json.loads(f.read())
            age_h = (time.time() - meta.get("ts", 0)) / 3600.0
            if age_h < cache_hours:
                print(f" -> 通讯录缓存 {age_h:.1f}h 前 freshness 有效(<{cache_hours:.0f}h)，跳过爬取")
                valid_ip_urls = open(url_cache_file, encoding="utf-8").read().splitlines()
                bestcf_cidr_urls = []
                if valid_ip_urls:
                    existing_urls = {s["url"] for s in URL_SOURCES}
                    for url in valid_ip_urls:
                        if url in existing_urls:
                            continue
                        existing_urls.add(url)
                        quality = "normal"
                        sample_limit = 1000
                        if "zip.cm.edu.kg/all.txt" in url:
                            quality = "bulk"
                            sample_limit = 3000
                        elif any(name in url.lower() for name in ["tiancheng", "vvhan", "gslege", "vps789"]):
                            quality = "premium"
                        URL_SOURCES.append({
                            "url": url, "type": "txt",
                            "quality": quality, "sample_limit": sample_limit
                        })
                    print(f" -> 缓存装载 {len(valid_ip_urls)} 个源链接")
                    print(f" -> 当前 IPv4 盲盒底池: {len(CF_CIDR_LIST)} 个网段")
                    print(f" -> 当前 IPv6 盲盒底池: {len(CF_IPV6_CIDR_LIST)} 个网段")
                    print("=" * 54)
                    return
        except Exception as e:
            print(f" -> 缓存读取异常({type(e).__name__})，走在线爬取")

    try:
        # 1. 尝试抓取 BestCF 页面主框架，寻找最新链接
        html_lines = fetch_text_lines("https://bestcf.cfmofa.eu.cc/")
        if not html_lines:
            raise ValueError("导航站访问失败或超时")

        bestcf_html = "\n".join(html_lines)
        scraped_urls = re.findall(r'<span class="url-text">(.*?)</span>', bestcf_html)

        valid_ip_urls = []
        bestcf_cidr_urls = []

        for raw_url in scraped_urls:
            url = raw_url.strip()
            if not url.startswith('http'):
                url = 'https://' + url

            # 只处理 .txt 结尾且排除订阅链接
            if url.endswith('.txt') and "sub://" not in url:
                if "/CIDR/" in url:
                    bestcf_cidr_urls.append(url)
                else:
                    valid_ip_urls.append(url)

        if not valid_ip_urls:
            raise ValueError("导航站页面结构改变或无有效链接")

        # 抓取成功，将 IP 链接保存到本地通讯录
        with open(url_cache_file, "w", encoding="utf-8") as f:
            f.write("\n".join(valid_ip_urls))
        try:
            with open(cache_meta, "w", encoding="utf-8") as f:
                json.dump({"ts": time.time()}, f)
        except Exception:
            pass
        print(f" -> 已成功获取并更新 {len(valid_ip_urls)} 个源链接到 latest_urls.txt")

    except Exception as e:
        # 断网兜底逻辑：读取本地通讯录
        print(f" -> 导航站获取异常 ({e})")
        print(" -> ⚠️ 触发断网兜底：读取本地链接缓存 latest_urls.txt")
        valid_ip_urls = []
        bestcf_cidr_urls = [] # 如果断网，CIDR网段就不强求更新了，走脚本内置底池

        if os.path.exists(url_cache_file):
            try:
                with open(url_cache_file, "r", encoding="utf-8") as f:
                    valid_ip_urls = f.read().splitlines()
                print(f" -> 成功恢复了 {len(valid_ip_urls)} 个历史源链接")
            except Exception as read_e:
                print(f" -> 本地缓存读取失败: {read_e}")

        # 终极底裤：如果连缓存文件都没有（全新机器第一次跑又刚好断网）
        if not valid_ip_urls:
            print(" -> 无可用缓存，启用内置备胎巨无霸链接")
            valid_ip_urls = [
                "https://zip.cm.edu.kg/all.txt",
                "https://mirror.ghproxy.com/https://raw.githubusercontent.com/gslege/CloudflareIP/main/All.txt"
            ]

    # 将有效链接装载进 URL_SOURCES 测速池并去重
    existing_urls = {s["url"] for s in URL_SOURCES}
    for url in valid_ip_urls:
        if url in existing_urls:
            continue
        existing_urls.add(url)
        quality = "normal"
        sample_limit = 1000

        # 特殊限流：CM巨无霸，限制抽样，防止撑爆内存
        if "zip.cm.edu.kg/all.txt" in url:
            quality = "bulk"
            sample_limit = 3000
        # 精选源打标
        elif any(name in url.lower() for name in ["tiancheng", "vvhan", "gslege", "vps789"]):
            quality = "premium"

        URL_SOURCES.append({
            "url": url,
            "type": "txt",
            "quality": quality,
            "sample_limit": sample_limit
        })

    print(f" -> 当前加载待测的具体 IP 源总数: {len(URL_SOURCES)} 个")

    # ----------------------------------------------------
    #  任务二：抓取各类神仙 CIDR 网段，并扩充到底池 (保持原有逻辑)
    # ----------------------------------------------------
    added_cidr_count = 0
    cidr_v4_regex = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$')
    cidr_v6_regex = re.compile(r'^([0-9a-fA-F:]+)/\d{1,3}$')

    if bestcf_cidr_urls: # 只有网络畅通并抓到了才执行扩充
        # (A) 抓取 BaiPiao 的 IPv4 和 IPv6 网段
        for line in fetch_text_lines("https://www.baipiao.eu.org/cloudflare/ips-v4"):
            line = line.strip()
            if cidr_v4_regex.match(line) and line not in CF_CIDR_LIST:
                CF_CIDR_LIST.append(line)
                added_cidr_count += 1

        for line in fetch_text_lines("https://www.baipiao.eu.org/cloudflare/ips-v6"):
            line = line.strip()
            if cidr_v6_regex.match(line) and line not in CF_IPV6_CIDR_LIST:
                CF_IPV6_CIDR_LIST.append(line)
                added_cidr_count += 1

        # (B) 深入抓取刚才找出来的 BestCF "真香定律" 网段
        for cidr_url in bestcf_cidr_urls:
            for line in fetch_text_lines(cidr_url):
                line = line.strip()
                if cidr_v4_regex.match(line) and line not in CF_CIDR_LIST:
                    CF_CIDR_LIST.append(line)
                    added_cidr_count += 1
                elif cidr_v6_regex.match(line) and line not in CF_IPV6_CIDR_LIST:
                    CF_IPV6_CIDR_LIST.append(line)
                    added_cidr_count += 1

        print(f" -> 已自动合并 {added_cidr_count} 个最新 CIDR 网段")

    print(f" -> 当前 IPv4 盲盒底池: {len(CF_CIDR_LIST)} 个网段")
    print(f" -> 当前 IPv6 盲盒底池: {len(CF_IPV6_CIDR_LIST)} 个网段")
    print("=" * 54)