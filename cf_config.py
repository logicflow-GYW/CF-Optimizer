# ============================================================
#  CF Optimizer v3.4 — 配置文件 (海陆空全自动进货终极版)
#  v4.2 改动：移除 VIP 功能，新增 Range 检测开关
# ============================================================
import os
import urllib.request
import re

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
    "CN", "RU", "KP", #"HK",
    "MO"
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
MAX_TASK_LIMIT       = 3000   # 入口探测最大任务数（shuffle 后截断）
RANDOM_SCAN_COUNT    = 10000  # 每次随机扫描的 CF CIDR IP 数量（从网段中抽盲盒的数量）

MAX_TCP_WORKERS      = 500    # TCP 连通性探测并发数
MAX_TRACE_WORKERS    = 100    # /cdn-cgi/trace 并发数
MAX_API_WORKERS      = 20     # 代理能力 API 验证并发数
MAX_TTFB_WORKERS     = 50     # TTFB 延迟测试并发数
MAX_BW_WORKERS       = 10     # 下载测速并发数
MAX_PURITY_WORKERS   = 2      # ip-api.com 纯净度检测并发数

TCP_TIMEOUT          = 1.0    # TCP 连接超时（秒）
TRACE_TIMEOUT        = 4.0    # /trace 请求超时（秒）
TTFB_MAX             = 0.8    # TTFB 上限（秒），超过则淘汰
BW_MB                = 10     # 测速下载大小（MB）
BW_TIMEOUT           = 15.0   # 测速超时（秒）
BW_EARLY_STOP_MBPS   = 80.0   # 达到此速度后提前结束测速（Mbps）

# ────────────────────────────────────────────────
#  流水线内部限制
# ────────────────────────────────────────────────
TCP_ALIVE_LIMIT      = 1000
TTFB_POOL_LIMIT      = 80
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
WORKER_HOST     = os.environ.get("CF_WORKER_HOST", "https://your-worker.example.com")
WORKER_PASSWORD = os.environ.get("CF_WORKER_PASSWORD", "")

NOTIFY_WEBHOOK_URL = os.environ.get("CF_WEBHOOK_URL", "")
NOTIFY_TG_TOKEN   = os.environ.get("CF_TG_TOKEN", "")
NOTIFY_TG_CHAT_ID = os.environ.get("CF_TG_CHAT_ID", "")

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

# ============================================================
#  自动化网络爬虫模块：全自动获取最新源 (通讯录模式)
# ============================================================
print("\n" + "=" * 54)
print("启动动态通讯录：全自动获取最新订阅源链接...")

# 自动创建 Data 目录并存放通讯录缓存
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Data")
os.makedirs(DATA_DIR, exist_ok=True)
URL_CACHE_FILE = os.path.join(DATA_DIR, "latest_urls.txt")

def fetch_text_lines(url):
    """辅助函数：请求网址并按行返回文本，自带异常处理"""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
        content = urllib.request.urlopen(req, timeout=10).read().decode('utf-8')
        return content.splitlines()
    except Exception:
        return []

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
    with open(URL_CACHE_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(valid_ip_urls))
    print(f" -> 已成功获取并更新 {len(valid_ip_urls)} 个源链接到 latest_urls.txt")

except Exception as e:
    # 断网兜底逻辑：读取本地通讯录
    print(f" -> 导航站获取异常 ({e})")
    print(" -> ⚠️ 触发断网兜底：读取本地链接缓存 latest_urls.txt")
    valid_ip_urls = []
    bestcf_cidr_urls = [] # 如果断网，CIDR网段就不强求更新了，走脚本内置底池

    if os.path.exists(URL_CACHE_FILE):
        try:
            with open(URL_CACHE_FILE, "r", encoding="utf-8") as f:
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

# 将有效链接装载进 URL_SOURCES 测速池
for url in valid_ip_urls:
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

# ────────────────────────────────────────────────
#  智能多地区推送阈值
# ────────────────────────────────────────────────
SMART_PUSH_MIN_SCORE  = 30.0   # 地区平均评分下限（0~100），低于此不推
SMART_PUSH_MIN_NODES  = 3      # 地区至少要有几个节点才考虑
SMART_PUSH_IPS_PER_CC = 3      # 每个入选地区最多贡献几个 IP

# ────────────────────────────────────────────────
#  v4.2 已移除：TARGET_COUNTRIES（VIP 保送地区）
#  原 VIP 功能过度设计且与评分排序重叠，已废弃。
#  如需偏向特定国家，请用 ONLY_COUNTRIES 白名单。
# ────────────────────────────────────────────────
