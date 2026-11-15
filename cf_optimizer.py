#!/usr/bin/env python3
"""
CF Optimizer Entrance-Only v4.5 - 入口 IP 优选独立程序
=====================================================
版本：v4.6 (动态调优平滑平稳版)

第一轮修复内容 (v4.4):
  1. 修复 bulk_e 源未进入测试池
  2. 修复 RESERVE_CAND_START 不生效
  3. 修复 --top-n 在智能推送模式下不生效
  4. 修复 TCP 并发上限和默认值不一致
  5. 修复 dynamic_random_scan 逻辑（改为临时计算，不持久化）
  6. 合并输出时过滤过期结果
  7. 保存本地合并后的 ADD_merged.txt
  8. 记忆库清理后立即保存

第二轮优化内容 (v4.5):
  1. 统一节点模型为 IP:Port（不再中途只按 IP 去重）
  2. 纯 IP 源支持多端口展开
  3. TCP 阶段保留所有 IP:Port 组合
  4. 候选任务分层保留优先级（记忆库/备用池优先）
  5. 增强 IP 校验与公网过滤
  6. 网段去重粒度可配置（IPv4 /24, IPv6 /48）
  7. 启动时自动检测 IPv6 连通性

功能：
  - 收集 Cloudflare 各类 IP 资源（包含从订阅、内置 CIDR 盲扫、记忆库等）
  - TCP 连通性测试 + Trace 国家归属标签识别
  - 延迟（TTFB）与抖动测试 + Jitter 过滤
  - Range 选项支持检测（可选）
  - 测速下载带宽（固定时长）
  - 综合评分、CIDR 智能前缀去重以及国家地区多样性配额筛选
  - 智能合并网络标签，生成结果并推送到 Cloudflare Worker (ADD.txt)
"""
import sys, os, time, re, json, socket, asyncio, random, ipaddress, subprocess, logging, importlib, argparse
from urllib.parse import urlparse
from cf_memory import (
    load_memory, save_memory, record_result,
    get_priority_candidates, get_cidr_weights, prune_stale,
    get_node_confidence
)
import cf_autotune

# 强制控制台输出使用 UTF-8 编码，防止中文乱码
def parse_args():
    parser = argparse.ArgumentParser(description="CF Entrance Optimizer v4.6")
    parser.add_argument("--no-notify", action="store_true", help="禁用通知")
    parser.add_argument("--json-only", action="store_true", help="只输出 JSON，不推送 Worker")
    parser.add_argument("--top-n", type=int, help="覆盖 BW_TOP_N 和 SMART_PUSH_MAX_TOTAL")
    parser.add_argument("--reset-autotune", action="store_true", help="重置动态调优状态，回到配置默认值")
    parser.add_argument("--no-autotune", action="store_true", help="本轮禁用自动调节")
    return parser.parse_args()

args = parse_args()

_stdout_encoding = (sys.stdout.encoding or '').lower()
if _stdout_encoding != 'utf-8' and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# 确保脚本所在目录在 sys.path 中，解决其他工作目录下找不到配置文件的问题
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) if '__file__' in globals() else os.getcwd()
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

try:
    import cf_config
    from cf_config import (
        RUN_MODE, URL_SOURCES, EXCLUDE_COUNTRIES,
        MAX_TASK_LIMIT, RANDOM_SCAN_COUNT, MAX_TCP_WORKERS,
        MAX_TRACE_WORKERS, MAX_TTFB_WORKERS, MAX_BW_WORKERS,
        TCP_TIMEOUT, TRACE_TIMEOUT, TTFB_MAX, BW_MB, BW_TIMEOUT,
        BW_EARLY_STOP_MBPS, WORKER_ENABLE, WORKER_HOST, WORKER_PASSWORD, USER_AGENT,
        CF_PORTS, CF_HTTPS_PORTS, CF_CIDR_LIST, CF_IPV6_CIDR_LIST, IPV6_ENABLE,
        TCP_ALIVE_LIMIT, TCP_ALIVE_LIMIT_MIN, TCP_ALIVE_LIMIT_MAX, TTFB_POOL_LIMIT, BW_TOP_N, RESERVE_CAND_START, 
        RESERVE_CAND_END, RESERVE_MAX, NOTIFY_WEBHOOK_URL, NOTIFY_TG_TOKEN, NOTIFY_TG_CHAT_ID
    )
except ImportError:
    print("错误: 当前目录下未找到 cf_config.py 配置文件。")
    sys.exit(1)

if args.top_n:
    cf_config.BW_TOP_N = args.top_n
    cf_config.SMART_PUSH_MAX_TOTAL = args.top_n

VERSION = "4.6.0"

# ── 工具函数
def clamp(v, lo, hi):
    return max(lo, min(hi, v))

def is_valid_public_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return not (addr.is_private or addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_reserved or addr.is_link_local)
    except ValueError:
        return False

def compute_score(node) -> float:
    if len(node) < 6:
        return 0.0
    ttfb_ms = node[4] * 1000.0
    mbps = node[5]
    
    max_ttfb = getattr(cf_config, "SCORE_MAX_TTFB_MS", 800.0)
    ttfb_score = max(0.0, 1.0 - ttfb_ms / max_ttfb)
    
    max_bps = getattr(cf_config, "SCORE_MAX_BPS", 150.0)
    bw_score = min(1.0, mbps / max_bps)
    
    w_ttfb = getattr(cf_config, "SCORE_TTFB_WEIGHT", 0.6)
    w_bw = getattr(cf_config, "SCORE_BW_WEIGHT", 0.4)
    
    return w_ttfb * ttfb_score + w_bw * bw_score

SCRIPT_DIR     = os.path.dirname(os.path.abspath(__file__))

# 建立收纳目录
DATA_DIR = os.path.join(SCRIPT_DIR, "Data")
OUT_DIR  = os.path.join(SCRIPT_DIR, "Output")
LOG_DIR  = os.path.join(SCRIPT_DIR, "Logs")
for d in [DATA_DIR, OUT_DIR, LOG_DIR]:
    os.makedirs(d, exist_ok=True)

# 文件归属
LOG_FILE       = os.path.join(LOG_DIR, "cf_entrance_optimizer.log")
RESERVE_FILE   = os.path.join(DATA_DIR, "reserve_ips.txt")
V6_SEED_FILE   = os.path.join(DATA_DIR, "ipv6_seeds.txt")  # 2026-11-11: IPv6 备用池保底
AUTOTUNE_FILE  = os.path.join(DATA_DIR, "autotune_state.json")

logger = logging.getLogger("CFEntranceOptimizer")
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    fh = logging.FileHandler(LOG_FILE, encoding='utf-8')
    log_level = logging.DEBUG if getattr(cf_config, "DEBUG_MODE", False) else logging.INFO
    fh.setLevel(log_level)

    if log_level == logging.DEBUG:
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] <%(filename)s:%(lineno)d> %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    else:
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    fh.setFormatter(formatter)
    logger.addHandler(fh)
    logger.propagate = False

# ==========================================
# 智能调优状态机 (Auto-Tuning State) - v4.6
# ==========================================
# 临时定义一个 cprint，防止在加载配置时因未定义 cprint 报错（实际的 cprint 在后面定义）
def cprint(msg, log=True, level="info", end="\n", flush=False):
    print(msg, end=end, flush=flush)
    if log and "\r" not in msg:
        clean_msg = re.sub(r'\033\[.*?m', '', msg).strip()
        if 'logger' in globals() and logger:
            getattr(logger, level)(clean_msg)

# 处理命令行重置参数
if getattr(args, "reset_autotune", False):
    cf_autotune.reset_state(AUTOTUNE_FILE)

# 默认状态模板
default_tune_state = {
    "best_tcp_workers": getattr(cf_config, "MAX_TCP_WORKERS", 500),
    "dynamic_ttfb_max": getattr(cf_config, "TTFB_MAX", 0.8),
    "dynamic_task_limit": getattr(cf_config, "MAX_TASK_LIMIT", 2000),
    "dynamic_early_stop": getattr(cf_config, "BW_EARLY_STOP_MBPS", 80.0),
    "dynamic_bw_workers": getattr(cf_config, "MAX_BW_WORKERS", 10),
    "dynamic_bw_mb": getattr(cf_config, "BW_MB", 10),

    "dyn_tcp_timeout": getattr(cf_config, "TCP_TIMEOUT", 1.0),
    "dyn_trace_workers": getattr(cf_config, "MAX_TRACE_WORKERS", 100),
    "dyn_ttfb_workers": getattr(cf_config, "MAX_TTFB_WORKERS", 50),
    "dyn_ttfb_pool": getattr(cf_config, "TTFB_POOL_LIMIT", 80),
    "dyn_jitter": getattr(cf_config, "TTFB_JITTER_LIMIT", 0.20),
    "dyn_tcp_alive_limit": getattr(cf_config, "TCP_ALIVE_LIMIT", 1500),

    "task_limit_up_streak": 0,
    "task_limit_down_streak": 0,
    "pid_loss_integral": 0.0,
    "pid_last_loss_error": 0.0,
    "history": []
}

AUTOTUNE_ACTIVE = cf_config.AUTOTUNE_ENABLE and not getattr(args, "no_autotune", False)

if AUTOTUNE_ACTIVE:
    tune_state = cf_autotune.load_state(AUTOTUNE_FILE, default_tune_state)
    
    # 应用现有及新增动态参数
    cf_config.MAX_TCP_WORKERS = tune_state.get("best_tcp_workers", cf_config.MAX_TCP_WORKERS)
    cf_config.TTFB_MAX = tune_state.get("dynamic_ttfb_max", cf_config.TTFB_MAX)
    cf_config.MAX_TASK_LIMIT = tune_state.get("dynamic_task_limit", cf_config.MAX_TASK_LIMIT)
    cf_config.BW_EARLY_STOP_MBPS = tune_state.get("dynamic_early_stop", cf_config.BW_EARLY_STOP_MBPS)
    cf_config.MAX_BW_WORKERS = tune_state.get("dynamic_bw_workers", cf_config.MAX_BW_WORKERS)
    cf_config.BW_MB = tune_state.get("dynamic_bw_mb", cf_config.BW_MB)
    
    cf_config.TCP_TIMEOUT = tune_state.get("dyn_tcp_timeout", cf_config.TCP_TIMEOUT)
    cf_config.MAX_TRACE_WORKERS = tune_state.get("dyn_trace_workers", cf_config.MAX_TRACE_WORKERS)
    cf_config.MAX_TTFB_WORKERS = tune_state.get("dyn_ttfb_workers", cf_config.MAX_TTFB_WORKERS)
    cf_config.TTFB_POOL_LIMIT = tune_state.get("dyn_ttfb_pool", cf_config.TTFB_POOL_LIMIT)
    cf_config.TCP_ALIVE_LIMIT = tune_state.get("dyn_tcp_alive_limit", cf_config.TCP_ALIVE_LIMIT)
    # [修复] 避免未定义变量而在加载时导致崩溃。此处不需要做多余的 TCP_ALIVE_LIMIT 重复赋值
else:
    tune_state = default_tune_state.copy()
    print("ℹ️ 本轮已禁用自动调优，将使用静态配置默认值")

def write_autotune_state(state):
    if AUTOTUNE_ACTIVE:
        cf_autotune.write_state(AUTOTUNE_FILE, state)

# ── IPv6 / IPv4 正则与工具函数
IPV6_RE = re.compile(
    r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,7}:'
    r'|:(?::[0-9a-fA-F]{1,4}){1,7}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}'
    r'|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}'
    r'|::(?:[fF]{4}(?::0{1,4})?:)?(?:25[0-5]|2[0-4]\d|\d\d?)'
    r'|::'
)
IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def ip_family(ip: str) -> int:
    try:
        addr = ipaddress.ip_address(ip)
        return socket.AF_INET6 if isinstance(addr, ipaddress.IPv6Address) else socket.AF_INET
    except ValueError:
        return socket.AF_INET

def check_env():
    cprint("正在检查运行环境...")
    logger.info(f"启动 CF Entrance Optimizer v{VERSION}，Python 版本 {sys.version.split()[0]}")
    if sys.version_info < (3, 8):
        cprint("错误: 需要 Python 3.8 或以上版本", level="error")
        sys.exit(1)
    try:
        import aiohttp
    except ImportError:
        cprint("正在安装 aiohttp 依赖库...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "aiohttp"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        importlib.invalidate_caches()
        cprint("aiohttp 安装成功")
    cprint("环境准备完毕\n")

check_env()
import aiohttp
from aiohttp.abc import AbstractResolver

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

class SingleIPResolver(AbstractResolver):
    def __init__(self, ip: str):
        self._ip = ip
        self._family = ip_family(ip)

    async def resolve(self, host, port=0, family=socket.AF_INET):
        return [{"hostname": host, "host": self._ip, "port": port,
                 "family": self._family, "proto": 0, "flags": socket.AI_NUMERICHOST}]

    async def close(self):
        pass

def scheme_for(port: int) -> str:
    return "https" if port in cf_config.CF_HTTPS_PORTS else "http"

MERGE_LINE_RE = re.compile(r"^(?:(?:\[?[0-9a-fA-F:]+\]?)|(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})):(\d{1,5})#[A-Z]{2}-\[.+\]$")

def load_file_entries(filepath: str, with_cc: bool = False) -> list:
    if not os.path.exists(filepath):
        return []
    entries = []
    with open(filepath, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if with_cc:
                m = re.match(r"^([0-9a-fA-F:\.]+):(\d{1,5})#(.*)", line)
                if m:
                    port = int(m.group(2))
                    if 1 <= port <= 65535:
                        entries.append((m.group(1), port, m.group(3)))
            else:
                m = re.match(r"^([0-9a-fA-F:\.]+):(\d{1,5})", line)
                if m:
                    port = int(m.group(2))
                    if 1 <= port <= 65535:
                        entries.append((m.group(1), port))
    return entries

def generate_random_ips(count: int, weights: list = None, ipv6: bool = False) -> list:
    if count <= 0:
        return []

    nets = []
    if ipv6 and cf_config.IPV6_ENABLE:
        for c in cf_config.CF_IPV6_CIDR_LIST:
            try:
                nets.append(ipaddress.IPv6Network(c, strict=False))
            except ValueError:
                pass
        w = [1] * len(nets) if nets else []
    else:
        for c in cf_config.CF_CIDR_LIST:
            try:
                net = ipaddress.IPv4Network(c, strict=False)
                if net.num_addresses >= 4:
                    nets.append(net)
            except ValueError:
                pass
        w = weights if (weights and len(weights) == len(nets)) else [n.num_addresses for n in nets]

    if not nets:
        return []

    result: set[str] = set()
    for _ in range(count * 5):
        if len(result) >= count:
            break
        net = random.choices(nets, weights=w, k=1)[0]
        total = net.num_addresses
        offset = random.randint(1, max(1, total - 2))
        result.add(str(net.network_address + offset))
    return [(ip, 443) for ip in result]

NET_NAME_CACHE = os.path.join(DATA_DIR, "last_net_name.txt")


async def get_current_net_name() -> str:
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            async with session.get("http://ip-api.com/json/?lang=zh-CN&fields=isp") as r:
                if r.status == 200:
                    data = await r.json()
                    isp_raw = data.get("isp", "Default")
                    isp = isp_raw.lower()
                    if "mobile" in isp:
                        name = "Mobile"
                    elif "unicom" in isp:
                        name = "Unicom"
                    elif "telecom" in isp:
                        name = "Telecom"
                    else:
                        name = re.sub(r'[^a-zA-Z0-9\u4e00-\u9fa5]', '_', isp_raw)
                    # 探测成功 → 缓存，供下次探测失败时沿用
                    try:
                        with open(NET_NAME_CACHE, "w", encoding="utf-8") as f:
                            f.write(name)
                    except Exception:
                        pass
                    return name
    except Exception as e:
        logger.debug(f"get_current_net_name 失败: {type(e).__name__}: {e}")
    # 2026-11-11: 探测失败时沿用上次成功的网络名，避免生成 entry_ip_DefaultNet.txt 把
    # 同一网络的结果拆成两个文件（合并时会变成一堆重复条目、Worker 侧还会当成两个网络）
    try:
        if os.path.exists(NET_NAME_CACHE):
            cached = open(NET_NAME_CACHE, encoding="utf-8").read().strip()
            if cached:
                cprint(f"   ⚠️ 网络名探测失败，沿用上次结果: {cached}", level="warning")
                return cached
    except Exception:
        pass
    return "DefaultNet"

async def check_ipv6_connectivity() -> bool:
    """检测 IPv6 连通性（v4.6.1 修订）
    旧版拿 CF 公共 DNS 解析器 2606:4700:4700::1111 做裸 TCP:443 探测——该地址不开放 443，
    真机 ping6 通但 TCP 超时，导致 IPv6 被连续 5 轮误关（2026-11-11 诊断报告 §2b）。
    现默认改用 HTTP GET /cdn-cgi/trace 打真实边缘 v6，并放宽超时至 5s。
    """
    if not getattr(cf_config, "IPV6_AUTO_DETECT", True):
        return cf_config.IPV6_ENABLE

    host = getattr(cf_config, "IPV6_TEST_HOST", "2403:18c0:4:5fd:be24:11ff:fe74:78ba")
    port = int(getattr(cf_config, "IPV6_TEST_PORT", 443))
    timeout = float(getattr(cf_config, "IPV6_TEST_TIMEOUT", 5))
    mode = str(getattr(cf_config, "IPV6_TEST_MODE", "http")).lower()
    try:
        if mode == "http":
            connector = aiohttp.TCPConnector(resolver=SingleIPResolver(host), ssl=True)
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as sess:
                async with sess.get(
                    f"https://cp.cloudflare.com:{port}/cdn-cgi/trace",
                    headers={"Host": "cp.cloudflare.com", "User-Agent": cf_config.USER_AGENT}
                ) as r:
                    ok = r.status == 200 and "v6" in (await r.text())
                    if not ok and r.status == 200:
                        # trace 文本里没有显式 v6 标记也没关系，200 即证明 v6 应用层可达
                        ok = True
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            ok = True
        if ok:
            cprint("   ✓ IPv6 连通性检测通过")
            return True
        raise RuntimeError("HTTP probe returned non-200")
    except Exception as e:
        logger.debug(f"IPv6 连通性检测失败: {type(e).__name__}: {e}")
        cprint(f"   ✗ IPv6 检测未通过({type(e).__name__})，已自动关闭 IPv6 扫描", level="warning")
        return False


async def fetch_urls_classified(sources):
    premium_entries, normal_entries, bulk_entries = [], [], []

    timeout = aiohttp.ClientTimeout(total=getattr(cf_config, "FETCH_TOTAL_TIMEOUT", 20.0))
    per_host_limit = int(getattr(cf_config, "FETCH_PER_HOST_LIMIT", 8))
    retry_n = int(getattr(cf_config, "FETCH_RETRY", 1))
    health = load_source_health()
    health_changed = False

    # ── 源健康度闸门：连续失败 N 轮的源本轮跳过，每 SOURCE_RETRY_AFTER 轮强制重试一次
    active_sources = []
    skipped_sources = []
    round_key = time.strftime("%Y%m%d%H")
    for s in sources:
        u = s["url"]
        h = health.get(u, {})
        fails = h.get("fail_streak", 0)
        if fails >= getattr(cf_config, "SOURCE_FAIL_SKIP", 3):
            last_try = h.get("last_round", "")
            try_round = h.get("try_round", 0)
            if last_try != round_key:
                h["try_round"] = try_round + 1
                h["last_round"] = round_key
                health[u] = h
                health_changed = True
                if (try_round + 1) % getattr(cf_config, "SOURCE_RETRY_AFTER", 4) != 0:
                    skipped_sources.append(u)
                    continue
        active_sources.append(s)
    if skipped_sources:
        cprint(f"   ⏭️  连续失败退避：本轮跳过 {len(skipped_sources)} 个源（每 {getattr(cf_config, 'SOURCE_RETRY_AFTER', 4)} 轮重试一次）")

    async with aiohttp.ClientSession(headers={"User-Agent": cf_config.USER_AGENT}, timeout=timeout) as session:
        async def _fetch_one(src):
            url, quality, is_html, limit = (
                src["url"], src["quality"],
                src["type"] == "html", src.get("sample_limit", 0)
            )
            cprint(f"   [{quality.upper():7s}] 正在获取: {url}")
            local_entries = []
            local_seen = set()  # 改为按 (ip, port) 去重
            last_err = None
            for attempt in range(1 + max(0, retry_n)):
                try:
                    async with session.get(url) as r:
                        text = await r.text()
                    last_err = None
                    break
                except Exception as e:
                    last_err = e
                    await asyncio.sleep(0.5 * (attempt + 1))
            if last_err is None:
                if is_html:
                    for ip in IPV4_RE.findall(text):
                        if is_valid_public_ip(ip):  # 使用增强的校验
                            for p in cf_config.CF_PORTS:
                                key = (ip, p)
                                if key not in local_seen:
                                    local_seen.add(key)
                                    local_entries.append((ip, p))
                    if cf_config.IPV6_ENABLE:
                        for ip in IPV6_RE.findall(text):
                            try:
                                ipaddress.IPv6Address(ip)
                            except ValueError:
                                continue
                            if is_valid_public_ip(ip):
                                key = (ip, 443)
                                if key not in local_seen:
                                    local_seen.add(key)
                                    local_entries.append((ip, 443))
                else:
                    for line in text.splitlines():
                        raw = line.split('#')[0].strip()
                        # 明确端口的 IP:Port 格式
                        m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$", raw)
                        if m:
                            ip, port = m.group(1), int(m.group(2))
                            if 1 <= port <= 65535 and is_valid_public_ip(ip):
                                key = (ip, port)
                                if key not in local_seen:
                                    local_seen.add(key)
                                    local_entries.append((ip, port))
                            continue
                        # 纯 IP，端口标记为 None（后续展开）
                        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", raw) and is_valid_public_ip(raw):
                            key = (raw, None)
                            if key not in local_seen:
                                local_seen.add(key)
                                local_entries.append((raw, None))
                            continue
                        # IPv6
                        if cf_config.IPV6_ENABLE:
                            m6 = re.match(r"^\[([^\]]+)\]:(\d{1,5})$", raw)
                            if m6:
                                ip6, port = m6.group(1), int(m6.group(2))
                            elif IPV6_RE.fullmatch(raw):
                                ip6, port = raw, None
                            else:
                                ip6 = None
                            if ip6:
                                try:
                                    ipaddress.IPv6Address(ip6)
                                    if is_valid_public_ip(ip6):
                                        key = (ip6, port)
                                        if key not in local_seen:
                                            local_seen.add(key)
                                            local_entries.append((ip6, port))
                                except ValueError:
                                    pass

                if limit > 0 and len(local_entries) > limit:
                    random.shuffle(local_entries)
                    local_entries = local_entries[:limit]
                cprint(f"   [{quality.upper():7s}] 获取到 {len(local_entries)} 条: {url}")
                if url in health and health[url].get("fail_streak", 0):
                    health[url]["fail_streak"] = 0
                    health_changed = True
            else:
                h = health.setdefault(url, {})
                h["fail_streak"] = h.get("fail_streak", 0) + 1
                h["last_round"] = round_key
                health_changed = True
                # 2026-11-11: 失败必须显式可见（此前只在 DEBUG 级，DNS 故障时整轮静默 0 条差点被误读成"源都死了"）
                logger.warning(f"获取失败 {url}: {type(last_err).__name__}: {last_err}")
                cprint(f"   ✗ 获取失败({type(last_err).__name__}) 连败 {h['fail_streak']}: {url}", log=False)
            return quality, local_entries

        # ── 按域名分桶限流：78 个 URL 同属 bestcf.pages.dev 时一次性 gather 会自我压垮
        host_count = {}
        host_sem = {}
        for s in active_sources:
            h = urlparse(s["url"]).netloc
            if h not in host_sem:
                host_sem[h] = asyncio.Semaphore(max(1, per_host_limit))
            host_count[h] = host_count.get(h, 0) + 1
        if any(c > per_host_limit for c in host_count.values()):
            hot = sorted(host_count.items(), key=lambda x: -x[1])[:3]
            cprint(f"   🚦 源按域名限流：每域名并发 ≤{per_host_limit}（热点: " + ", ".join(f"{h}×{c}" for h, c in hot) + "）")

        async def _bounded(src):
            async with host_sem[urlparse(src["url"]).netloc]:
                return await _fetch_one(src)

        results = await asyncio.gather(*[_bounded(s) for s in active_sources])

    if health_changed:
        save_source_health(health)

    for quality, entries in results:
        if quality == "premium":
            premium_entries.extend(entries)
        elif quality == "normal":
            normal_entries.extend(entries)
        else:
            bulk_entries.extend(entries)

    return premium_entries, normal_entries, bulk_entries

def load_source_health() -> dict:
    path = getattr(cf_config, "SOURCE_HEALTH_FILE", None)
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_source_health(health: dict):
    path = getattr(cf_config, "SOURCE_HEALTH_FILE", None)
    if not path:
        return
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(health, f, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception as e:
        logger.debug(f"source_health 写盘失败: {e}")


async def collect_all_ips(load_premium: bool = False, cidr_weights: list = None, priority_ips: list = None) -> list:
    cprint("正在收集 IP 资源...")
    
    # 分层收集，按 (ip, port) 去重
    priority_tasks = []
    reserve_tasks = []
    premium_tasks = []
    normal_tasks = []
    bulk_tasks = []
    random_tasks = []
    
    seen_entries = set()  # 改为按 (ip, port) 去重

    # 第一层：记忆库优先节点
    if priority_ips:
        cprint(f"   已加载 {len(priority_ips)} 个记忆库优先节点")
        for ip, port, cc in priority_ips:
            key = (ip, port)
            if key not in seen_entries:
                seen_entries.add(key)
                priority_tasks.append((ip, port))

    # 第二层：备用池
    nodes = load_file_entries(RESERVE_FILE, with_cc=True)
    for ip, port, cc in nodes:
        key = (ip, port)
        if key not in seen_entries:
            seen_entries.add(key)
            reserve_tasks.append((ip, port))

    # 第三层：订阅源（分 premium/normal/bulk）
    premium_e, normal_e, bulk_e = await fetch_urls_classified(cf_config.URL_SOURCES)

    def add_entries(entries, task_list):
        """统一的条目添加函数，支持端口展开"""
        for ip, port in entries:
            if port is None:
                # 纯 IP，展开所有 CF 端口
                for p in cf_config.CF_PORTS:
                    key = (ip, p)
                    if key not in seen_entries:
                        seen_entries.add(key)
                        task_list.append((ip, p))
            else:
                # 明确端口，只使用该端口
                key = (ip, port)
                if key not in seen_entries:
                    seen_entries.add(key)
                    task_list.append((ip, port))

    add_entries(premium_e, premium_tasks)
    add_entries(normal_e, normal_tasks)
    add_entries(bulk_e, bulk_tasks)

    # 第四层：随机 CIDR 扫描
    static_ips_count = len(seen_entries)
    base_random_scan = RANDOM_SCAN_COUNT

    if static_ips_count > 1000:
        actual_scan_count = max(1000, int(base_random_scan * 0.2))
        cprint(f"   💡 静态源极充沛 ({static_ips_count} 个)，自动减少盲扫数量至 {actual_scan_count}")
    elif static_ips_count < 200:
        actual_scan_count = min(30000, base_random_scan * 2)
        cprint(f"   ⚠️ 静态源极少 ({static_ips_count} 个)，自动增加盲扫数量至 {actual_scan_count}")
    else:
        actual_scan_count = base_random_scan

    rand_ips = generate_random_ips(actual_scan_count, weights=cidr_weights, ipv6=False)
    if cf_config.IPV6_ENABLE:
        rand_ips += generate_random_ips(actual_scan_count // 2, ipv6=True)

    for ip, port in rand_ips:
        key = (ip, port)
        if key not in seen_entries:
            seen_entries.add(key)
            random_tasks.append((ip, port))

    # 分层截断保留优先级
    priority_min = getattr(cf_config, "PRIORITY_RESERVE_MIN", 50)
    reserve_min = getattr(cf_config, "RESERVE_POOL_MIN", 100)
    premium_min = getattr(cf_config, "PREMIUM_SOURCE_MIN", 200)
    
    final_tasks = []
    final_tasks.extend(priority_tasks[:priority_min])
    final_tasks.extend(reserve_tasks[:reserve_min])
    final_tasks.extend(premium_tasks[:premium_min])
    
    remaining = cf_config.MAX_TASK_LIMIT - len(final_tasks)
    if remaining > 0:
        pool = normal_tasks + bulk_tasks + random_tasks
        random.shuffle(pool)
        final_tasks.extend(pool[:remaining])
    
    cprint(f"   共收集到 {len(final_tasks)} 个 IP:Port 用于测试")
    cprint(f"   其中：优先 {len(priority_tasks[:priority_min])} | 备用 {len(reserve_tasks[:reserve_min])} | Premium {len(premium_tasks[:premium_min])} | 其他 {min(len(pool), remaining)}")
    
    return final_tasks

def save_json_result(nodes: list, filepath: str, net_name: str, compute_score_func):
    out = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "net_name": net_name,
        "count": len(nodes),
        "nodes": [
            {
                "ip": n[0], "port": n[1], "cc": n[3],
                "ttfb_ms": round(n[4] * 1000, 1) if len(n) > 4 else None,
                "mbps": round(n[5], 2) if len(n) > 5 else None,
                "score": round(compute_score_func(n) * 100, 1) if len(n) > 5 else None,
            }
            for n in nodes
        ]
    }
    json_path = filepath.replace(".txt", ".json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    return json_path

def select_entry_ips_basket(results: list, top_n: int) -> list:
    """网段去重选择，使用可配置的前缀长度"""
    cidr_seen = {}
    selected = []
    
    ipv4_prefix = getattr(cf_config, "IPV4_DEDUP_PREFIX", 24)
    ipv6_prefix = getattr(cf_config, "IPV6_DEDUP_PREFIX", 48)

    for item in results:
        ip = item[0]
        try:
            if ":" in ip:
                # IPv6
                net = ipaddress.IPv6Network(f"{ip}/{ipv6_prefix}", strict=False)
                prefix = str(net.network_address)
            else:
                # IPv4
                net = ipaddress.IPv4Network(f"{ip}/{ipv4_prefix}", strict=False)
                prefix = str(net.network_address)
        except ValueError:
            prefix = ip

        if prefix in cidr_seen:
            continue

        cidr_seen[prefix] = True
        selected.append(item)
        if len(selected) >= top_n:
            break

    return selected

# ── 地区分层与路由诊断（2026-11-11 新增）─────────────────────────────
# 设计要点（实测依据见 cf_config.py 注释）：
#   1. 基线用「该地区最好 K 个节点的 TTFB 均值」：中位数会被绕路簇拉高（SG 中位 1502ms 但 p25=263ms），
#      最小值对单次抖动太敏感，best-K 两者兼顾。
#   2. 基线只决定「这个地区值不值得推、是不是绕路」，绝不进 compute_score（相对分会倒退）。
#   3. 分层名额按 T1>T2>T3 分配，避免 T1 吃光名额。

def compute_region_baseline(nodes: list, k: int = 3) -> float:
    """地区基线 = 该地区 TTFB 最好的 k 个节点的均值。空列表返回 None。"""
    tts = sorted(n[4] for n in nodes if len(n) >= 5)
    if not tts:
        return None
    kk = min(max(1, k), len(tts))
    return sum(tts[:kk]) / kk


def diagnose_region_route(cc: str, baseline_s: float) -> dict:
    """路由诊断：基线 / 物理下限。仅用于日志与诊断，不参与评分。"""
    dist_km = getattr(cf_config, "REGION_DISTANCE_KM", {}).get(cc)
    if not dist_km or not baseline_s:
        return {"ratio": None, "label": "无参考", "floor_ms": None}
    floor_s = 2 * dist_km * 1000 / 2e8  # 往返（秒）
    ratio = baseline_s / floor_s
    severe = float(getattr(cf_config, "ROUTE_DIAG_SEVERE", 20.0))
    warn = float(getattr(cf_config, "ROUTE_DIAG_WARN", 10.0))
    label = "严重绕路" if ratio > severe else ("偏绕路" if ratio > warn else "接近物理")
    return {"ratio": ratio, "label": label, "floor_ms": floor_s * 1000}


def classify_region_tiers(cc_groups: dict) -> dict:
    """把地区分成 T1/T2/T3/DROP。返回 {cc: {...}}，按 TTFB 基线升序。"""
    t1_ms = float(getattr(cf_config, "PUSH_TIER1_TTFB_MS", 450)) / 1000.0
    t2_ms = float(getattr(cf_config, "PUSH_TIER2_TTFB_MS", 1200)) / 1000.0
    t3_ms = float(getattr(cf_config, "PUSH_TIER3_TTFB_MS", 1600)) / 1000.0
    t2_mbps = float(getattr(cf_config, "PUSH_TIER2_MIN_MBPS", 10.0))
    k = int(getattr(cf_config, "REGION_BASELINE_K", 3))

    out = {}
    for cc, nodes in cc_groups.items():
        if not nodes:
            continue
        base = compute_region_baseline(nodes, k)
        if base is None:
            continue
        mbps = [n[5] for n in nodes if len(n) >= 6]
        bw_med = sorted(mbps)[len(mbps) // 2] if mbps else 0.0
        if base <= t1_ms:
            tier = "T1"
        elif base <= t2_ms and bw_med >= t2_mbps:
            tier = "T2"
        elif base <= t3_ms:
            tier = "T3"
        else:
            tier = "DROP"
        diag = diagnose_region_route(cc, base)
        out[cc] = {
            "tier": tier, "baseline_ms": base * 1000.0, "bw_med": bw_med,
            "n": len(nodes), "diag": diag,
        }
    return dict(sorted(out.items(), key=lambda x: x[1]["baseline_ms"]))


def save_region_baseline(snapshot: dict):
    """把本轮地区基线落到 Data/region_baseline.json，供跨轮对比（不参与本轮计算）。"""
    path = getattr(cf_config, "REGION_BASELINE_FILE", None)
    if not path:
        return
    try:
        hist = []
        if os.path.exists(path):
            try:
                hist = json.load(open(path, encoding="utf-8")).get("history", [])
            except Exception:
                hist = []
        hist.append({"ts": int(time.time()), "regions": snapshot})
        hist = hist[-8:]
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"history": hist}, f, ensure_ascii=False, indent=1)
        os.replace(tmp, path)
    except Exception as e:
        logger.debug(f"region_baseline 写盘失败: {e}")


def select_with_diversity(nodes: list, top_n: int, per_cc: int = 2) -> list:
    if not nodes:
        return []

    from collections import defaultdict
    cc_groups = defaultdict(list)
    for n in nodes:
        cc = n[3] if len(n) > 3 else "XX"
        cc_groups[cc].append(n)

    selected = []
    for cc, group in cc_groups.items():
        if len(group[0]) > 5:
            try:
                group_sorted = sorted(group, key=compute_score, reverse=True)
            except Exception:
                group_sorted = group
        else:
            group_sorted = sorted(group, key=lambda x: x[4])
        selected.extend(group_sorted[:per_cc])

    final = select_entry_ips_basket(selected, top_n)
    return final


async def run_entrance_pipeline(tasks: list, net_name: str, memory_db: dict, priority_ips: list = None):
    cprint("\n" + "=" * 54)
    cprint("开始运行入口 IP 测速")
    cprint("=" * 54)

    # ── 阶段 1：TCP 连通性探测
    controller = cf_autotune.PIDFeedbackController(
        target_sp=getattr(cf_config, 'PID_LOSS_RATE_TARGET', 0.80)
    )
    # 恢复上一轮 PID 积分状态（带衰减，防止历史累积导致死锁）
    pid_decay = getattr(cf_config, 'PID_INTEGRAL_DECAY', 0.5)
    controller.loss_integral = tune_state.get("pid_loss_integral", 0.0) * pid_decay
    controller.last_loss_error = tune_state.get("pid_last_loss_error", 0.0) * pid_decay

    # 划分批次以执行前馈式自适应探测 (10% 热身批次)
    warmup_size = clamp(len(tasks) // 10, 150, len(tasks))
    warmup_tasks = tasks[:warmup_size]
    main_tasks = tasks[warmup_size:]

    cprint(f"TCP 探测中 (先锋热身批次: {warmup_size} 个，初始并发 {cf_config.MAX_TCP_WORKERS})...")
    warmup_sem = asyncio.Semaphore(cf_config.MAX_TCP_WORKERS)
    warmup_completed = 0
    warmup_alive = 0

    async def probe_warmup(ip, port):
        nonlocal warmup_completed, warmup_alive
        lat = None
        async with warmup_sem:
            try:
                start = time.monotonic()
                _, w = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=cf_config.TCP_TIMEOUT
                )
                lat = time.monotonic() - start
                warmup_alive += 1
                record_result(memory_db, ip, port, "", passed=True, stage="tcp")
            except Exception:
                key = f"{ip}:{port}"
                if key in memory_db:
                    record_result(memory_db, ip, port, "", passed=False, stage="fail")
            else:
                try:
                    w.close()
                    await w.wait_closed()
                except Exception:
                    pass
        warmup_completed += 1
        return ip, port, lat

    warmup_res = await asyncio.gather(*[probe_warmup(i, p) for i, p in warmup_tasks])

    # 根据先锋批次进行负反馈前馈控制
    warmup_survival_rate = warmup_alive / warmup_size
    
    # [修复] 跨轮次持久化 PID 积分状态突变检测：若热身存活率与上一轮历史记录偏差大于 30%，清零积分防死锁
    last_survival = tune_state.get("last_survival_rate", 0.5)
    if abs(warmup_survival_rate - last_survival) > 0.3:
        controller.loss_integral = 0.0
        controller.last_loss_error = 0.0
        cprint("   🔄 检测到本轮网络环境发生突变，已智能重置 PID 积分器以加速自适应")
    
    # 记录本轮的热身批次存活率以供下轮对比
    tune_state["last_survival_rate"] = warmup_survival_rate
    warmup_lats = sorted([r[2] for r in warmup_res if r and r[2] is not None])
    warmup_median_rtt = cf_autotune.percentile(warmup_lats, 0.5) if warmup_lats else cf_config.TCP_TIMEOUT

    # [修复] 结合上一次的存活率，如存活率波动大于 30% 视作网络环境剧烈变化，清零 PID 积分重置
    last_survival = tune_state.get("last_survival_rate", 0.5)
    if abs(warmup_survival_rate - last_survival) > 0.3:
        controller.loss_integral = 0.0
        controller.last_loss_error = 0.0
        cprint("   🔄 检测到网络环境突变，已重置 PID 积分器以加速适配新网络")
    
    # 记录本轮的热身存活率，用于下一轮进行突变判定
    tune_state["last_survival_rate"] = warmup_survival_rate

    stats_sensor = {
        "survival_rate": warmup_survival_rate,
        "sample_size": warmup_size,
        "median_rtt": warmup_median_rtt,
        "high_level_fail": 0.0
    }

    new_workers, new_timeout, _ = controller.compute_control_signals(
        stats_sensor, cf_config, default_tune_state
    )

    cprint(f"   ⚡ 前馈控制评估：先锋批次存活率 {warmup_survival_rate*100:.1f}%, 中位延迟 {warmup_median_rtt*1000:.0f}ms")
    if new_workers != cf_config.MAX_TCP_WORKERS:
        cprint(f"      🚦 并发度反馈调节为: {new_workers} (原: {cf_config.MAX_TCP_WORKERS})")
        cf_config.MAX_TCP_WORKERS = new_workers
        tune_state["best_tcp_workers"] = new_workers
    if abs(new_timeout - cf_config.TCP_TIMEOUT) > 0.02:
        cprint(f"      ⚡ 延迟超时反馈调节为: {new_timeout:.2f}s (原: {cf_config.TCP_TIMEOUT:.2f}s)")
        cf_config.TCP_TIMEOUT = new_timeout
        tune_state["dyn_tcp_timeout"] = new_timeout

    if AUTOTUNE_ACTIVE:
        write_autotune_state(tune_state)

    # 4. 主力大部队探测
    main_res = []
    main_alive = 0
    if main_tasks:
        cprint(f"TCP 主力大部队探测中 (剩余 {len(main_tasks)} 个，应用自适应并发 {cf_config.MAX_TCP_WORKERS})...")
        main_sem = asyncio.Semaphore(cf_config.MAX_TCP_WORKERS)
        main_completed = 0
        total_main = len(main_tasks)

        async def probe_main(ip, port):
            nonlocal main_completed, main_alive
            lat = None
            async with main_sem:
                try:
                    start = time.monotonic()
                    _, w = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=cf_config.TCP_TIMEOUT
                    )
                    lat = time.monotonic() - start
                    main_alive += 1
                    record_result(memory_db, ip, port, "", passed=True, stage="tcp")
                except Exception:
                    key = f"{ip}:{port}"
                    if key in memory_db:
                        record_result(memory_db, ip, port, "", passed=False, stage="fail")
                else:
                    try:
                        w.close()
                        await w.wait_closed()
                    except Exception:
                        pass
            main_completed += 1
            if main_completed % max(1, total_main // 20) == 0 or main_completed == total_main:
                cprint(f"\r   主力进度 {main_completed}/{total_main}，存活 {main_alive}", log=False, end="", flush=True)
            return ip, port, lat

        main_res = await asyncio.gather(*[probe_main(i, p) for i, p in main_tasks])
        print()

    # 汇总数据
    res = warmup_res + main_res
    alive_count = warmup_alive + main_alive
    survival_rate = alive_count / max(1, len(tasks))

    # 第二轮优化：保留所有 IP:Port 组合，不再按 IP 去重
    alive = []
    for r in res:
        if r and r[2] is not None:
            alive.append((r[0], r[1], r[2]))  # (ip, port, latency)
    
    # 按延迟排序，取前 N 个
    alive.sort(key=lambda x: x[2])
    raw_alive_count = len(alive)  # 保存截断前的原始存活数量（用于后续健康度计算与高层失败率计算）
    if raw_alive_count > cf_config.TCP_ALIVE_LIMIT and getattr(cf_config, "TCP_ALIVE_KEEP_PRIORITY", True):
        # 2026-11-11: 分层保留——优先候选/备用池节点保底入围，剩余名额按延迟排序
        # （旧行为纯按延迟截断，随机把记忆库里的历史好节点切掉）
        prio_keys = set()
        for item in priority_ips or []:
            ip, port = item[0], item[1]
            prio_keys.add((ip, port))
        for ip, port, _cc in load_file_entries(RESERVE_FILE, with_cc=True):
            prio_keys.add((ip, port))
        prio_alive = [n for n in alive if (n[0], n[1]) in prio_keys][:cf_config.TCP_ALIVE_LIMIT]
        rest = [n for n in alive if (n[0], n[1]) not in set((x[0], x[1]) for x in prio_alive)]
        alive = (prio_alive + rest)[:cf_config.TCP_ALIVE_LIMIT]
        if len(prio_alive) > 0:
            cprint(f"   🔖 截断保护：{min(len(prio_alive), cf_config.TCP_ALIVE_LIMIT)} 个优先/备用节点保底入围")
    else:
        alive = alive[:cf_config.TCP_ALIVE_LIMIT]

    cprint(f"   发现 {raw_alive_count} 个存活节点（IP:Port 组合），保留前 {len(alive)} 个")

    if not alive:
        logger.warning("TCP 探测后没有存活节点")
        return

    # ── 阶段 2：/trace 获取国家代码
    cprint("正在检测节点所在国家/地区...")
    sem_tr = asyncio.Semaphore(cf_config.MAX_TRACE_WORKERS)
    tagged = []
    completed = 0
    trace_success_count = 0
    total_alive = len(alive)

    async def trace(node):
        nonlocal completed, trace_success_count
        url = f"{scheme_for(node[1])}://cp.cloudflare.com:{node[1]}/cdn-cgi/trace"
        async with sem_tr:
            try:
                connector = aiohttp.TCPConnector(
                    resolver=SingleIPResolver(node[0]), ssl=False, force_close=True
                )
                async with aiohttp.ClientSession(
                    connector=connector,
                    timeout=aiohttp.ClientTimeout(total=cf_config.TRACE_TIMEOUT)
                ) as sess:
                    # 2026-11-11: 失败重试 TRACE_RETRY 次（原一次超时即丢，Trace 阶段曾丢 8.7 倍节点）
                    text = None
                    for attempt in range(1 + int(getattr(cf_config, "TRACE_RETRY", 1))):
                        try:
                            async with sess.get(
                                url, headers={"Host": "cp.cloudflare.com", "User-Agent": cf_config.USER_AGENT}
                            ) as r:
                                if r.status == 200:
                                    text = await r.text()
                                    break
                        except Exception:
                            if attempt < int(getattr(cf_config, "TRACE_RETRY", 1)):
                                await asyncio.sleep(0.3)
                    if text:
                        trace_success_count += 1
                        for line in text.splitlines():
                            if line.startswith("loc="):
                                cc = line.split("=")[1].strip().upper()
                                record_result(memory_db, node[0], node[1], cc, passed=True, stage="trace")
                                if cc not in cf_config.EXCLUDE_COUNTRIES:
                                    if hasattr(cf_config, "ONLY_COUNTRIES") and cf_config.ONLY_COUNTRIES:
                                        if cc in cf_config.ONLY_COUNTRIES:
                                            tagged.append((*node, cc))
                                    else:
                                        tagged.append((*node, cc))
                                break
            except Exception:
                pass
        completed += 1
        if completed % max(1, total_alive // 10) == 0 or completed == total_alive:
            cprint(f"\r   国家/地区检测进度 {completed}/{total_alive}，有效 {len(tagged)}", log=False, end="", flush=True)

    await asyncio.gather(*[trace(n) for n in alive])
    print()
    cprint(f"   识别到 {len(tagged)} 个有效节点")
    if not tagged:
        return

        # ── 阶段 3：多轮 TTFB 延迟测试与 Jitter 过滤
    cprint("正在进行 TTFB 延迟与抖动测试...")
    sem_ttfb = asyncio.Semaphore(cf_config.MAX_TTFB_WORKERS)
    ttfb_passed = []
    completed = 0
    total_ttfb = len(tagged)

    jitter_eligible = 0
    jitter_ok = 0

    async def measure_ttfb(node):
        nonlocal completed, jitter_eligible, jitter_ok
        url = f"{scheme_for(node[1])}://cp.cloudflare.com:{node[1]}/generate_204?ed=2560"
        samples = []
        async with sem_ttfb:
            try:
                connector = aiohttp.TCPConnector(
                    resolver=SingleIPResolver(node[0]), ssl=False, force_close=True
                )
                async with aiohttp.ClientSession(
                    connector=connector,
                    timeout=aiohttp.ClientTimeout(total=cf_config.TTFB_MAX + 4)
                ) as sess:
                    for _ in range(3):
                        start = time.monotonic()
                        try:
                            async with sess.get(
                                url, headers={"Host": "cp.cloudflare.com", "User-Agent": cf_config.USER_AGENT}
                            ) as r:
                                if r.status in (200, 204):
                                    await r.read()
                                    samples.append(time.monotonic() - start)
                        except Exception:
                            pass
                        if len(samples) < 3:
                            await asyncio.sleep(0.1)
            except Exception:
                pass

        if len(samples) >= 2:
            jitter_eligible += 1
            samples.sort()
            median_ttfb = samples[len(samples) // 2]
            jitter = samples[-1] - samples[0]
            if jitter <= cf_config.TTFB_JITTER_LIMIT:
                jitter_ok += 1
                ttfb_passed.append((*node, median_ttfb))
        elif len(samples) == 1:
            ttfb_passed.append((*node, samples[0]))

        completed += 1
        cprint(f"\r   TTFB 测试 {completed}/{total_ttfb}，收集到 {len(ttfb_passed)} 个有效回复", log=False, end="", flush=True)

    await asyncio.gather(*[measure_ttfb(n) for n in tagged])
    print()

    jitter_pass_rate = jitter_ok / max(1, jitter_eligible) if jitter_eligible > 0 else 1.0

    # 动态延迟与参数自适应
    if ttfb_passed:
        ttfb_passed.sort(key=lambda x: x[4])
        strict_passed = [n for n in ttfb_passed if n[4] < cf_config.TTFB_MAX]
        target_pool_size = cf_config.TTFB_POOL_LIMIT

        # ── TTFB_MAX 延迟阈值平滑调整
        if len(strict_passed) >= target_pool_size:
            target_ttfb_max = max(cf_config.TTFB_MAX_FLOOR, cf_config.TTFB_MAX - 0.1)
            ttfb_passed = strict_passed
        else:
            worst_ttfb = ttfb_passed[:target_pool_size][-1][4]
            target_ttfb_max = min(cf_config.TTFB_MAX_CEIL, max(cf_config.TTFB_MAX + 0.1, worst_ttfb))
            ttfb_passed = ttfb_passed[:target_pool_size]

        new_ttfb_max, ttfb_max_changed = cf_autotune.smooth_update(
            cf_config.TTFB_MAX, target_ttfb_max,
            alpha=cf_config.AUTOTUNE_EMA_ALPHA,
            deadzone=cf_config.AUTOTUNE_DEADZONE,
            lo=cf_config.TTFB_MAX_FLOOR,
            hi=cf_config.TTFB_MAX_CEIL
        )
        if ttfb_max_changed:
            cprint(f"   🎯 TTFB 合格延迟阈值调整为: {new_ttfb_max:.2f}s (原: {cf_config.TTFB_MAX:.2f}s)")
            cf_config.TTFB_MAX = new_ttfb_max
            tune_state["dynamic_ttfb_max"] = new_ttfb_max

        # ── TTFB 池闸门自适应
        if len(strict_passed) >= target_pool_size * 2:
            target_pool = int(target_pool_size * 0.85)
        elif len(strict_passed) < target_pool_size:
            target_pool = int(target_pool_size * 1.20)
        else:
            target_pool = target_pool_size

        new_pool, pool_changed = cf_autotune.smooth_update(
            target_pool_size, target_pool,
            alpha=cf_config.AUTOTUNE_EMA_ALPHA,
            deadzone=cf_config.AUTOTUNE_DEADZONE,
            lo=cf_config.TTFB_POOL_MIN,
            hi=cf_config.TTFB_POOL_MAX,
            integer=True
        )
        if pool_changed:
            cprint(f"   📦 下一轮测速池最大数(TTFB_POOL_LIMIT)调整为: {new_pool} (原: {target_pool_size})")
            cf_config.TTFB_POOL_LIMIT = new_pool
            tune_state["dyn_ttfb_pool"] = new_pool

        # ── Jitter 抖动自适应
        if jitter_pass_rate < 0.35 and len(ttfb_passed) < cf_config.TTFB_POOL_LIMIT:
            target_jitter = cf_config.TTFB_JITTER_MAX
        else:
            target_jitter = cf_config.TTFB_JITTER_LIMIT
        
        new_jitter, jitter_changed = cf_autotune.smooth_update(
            cf_config.TTFB_JITTER_LIMIT, target_jitter,
            alpha=cf_config.AUTOTUNE_EMA_ALPHA,
            deadzone=cf_config.AUTOTUNE_DEADZONE,
            lo=cf_config.TTFB_JITTER_LIMIT,
            hi=cf_config.TTFB_JITTER_MAX
        )
        if jitter_changed:
            cprint(f"   ⚡ Jitter 过滤阈值调整为: {new_jitter:.2f}s (原: {cf_config.TTFB_JITTER_LIMIT:.2f}s)")
            cf_config.TTFB_JITTER_LIMIT = new_jitter
            tune_state["dyn_jitter"] = new_jitter

        # 计算健康度并调节 Trace / TTFB 并发数
        median_ttfb = ttfb_passed[len(ttfb_passed)//2][4] if ttfb_passed else cf_config.TTFB_MAX
        health = cf_autotune.network_health(survival_rate, median_ttfb, jitter_pass_rate, cf_config)
        
        trace_target = cf_config.TRACE_WORKERS_MIN + health * (cf_config.TRACE_WORKERS_MAX - cf_config.TRACE_WORKERS_MIN)
        ttfb_target = cf_config.TTFB_WORKERS_MIN + health * (cf_config.TTFB_WORKERS_MAX - cf_config.TTFB_WORKERS_MIN)
        
        new_trace_workers, trace_workers_changed = cf_autotune.smooth_update(
            cf_config.MAX_TRACE_WORKERS, trace_target,
            alpha=cf_config.AUTOTUNE_EMA_ALPHA,
            deadzone=cf_config.AUTOTUNE_DEADZONE,
            lo=cf_config.TRACE_WORKERS_MIN,
            hi=cf_config.TRACE_WORKERS_MAX,
            integer=True
        )
        if trace_workers_changed:
            cprint(f"   🚦 Trace 并发数调整为: {new_trace_workers} (原: {cf_config.MAX_TRACE_WORKERS})")
            cf_config.MAX_TRACE_WORKERS = new_trace_workers
            tune_state["dyn_trace_workers"] = new_trace_workers
            
        new_ttfb_workers, ttfb_workers_changed = cf_autotune.smooth_update(
            cf_config.MAX_TTFB_WORKERS, ttfb_target,
            alpha=cf_config.AUTOTUNE_EMA_ALPHA,
            deadzone=cf_config.AUTOTUNE_DEADZONE,
            lo=cf_config.TTFB_WORKERS_MIN,
            hi=cf_config.TTFB_WORKERS_MAX,
            integer=True
        )
        if ttfb_workers_changed:
            cprint(f"   🚦 TTFB 测试并发数调整为: {new_ttfb_workers} (原: {cf_config.MAX_TTFB_WORKERS})")
            cf_config.MAX_TTFB_WORKERS = new_ttfb_workers
            tune_state["dyn_ttfb_workers"] = new_ttfb_workers

        # [修复] 计算高层探测超时失败率 - 使用实际进入 Trace 的节点数作为分母，避免死亡螺旋
        actual_trace_input = min(raw_alive_count, cf_config.TCP_ALIVE_LIMIT)
        high_level_fail = 1.0 - (trace_success_count / max(1, actual_trace_input))
        
        all_lats = sorted([r[2] for r in res if r and r[2] is not None])
        overall_median_rtt = cf_autotune.percentile(all_lats, 0.5) if all_lats else cf_config.TCP_TIMEOUT

        stats_final = {
            "survival_rate": survival_rate,
            "sample_size": len(tasks),
            "median_rtt": overall_median_rtt,
            "high_level_fail": high_level_fail
        }

        # 通过控制器负反馈更新下一轮的池上限（TCP_ALIVE_LIMIT）并平滑回写
        _, _, new_alive_limit = controller.compute_control_signals(
            stats_final, cf_config, default_tune_state
        )

        # 持久化 PID 积分状态，下一轮可恢复（带衰减）
        tune_state["pid_loss_integral"] = controller.loss_integral
        tune_state["pid_last_loss_error"] = controller.last_loss_error

        if new_alive_limit != cf_config.TCP_ALIVE_LIMIT:
            # [修复] 避免多重截断冲突，仅记录建议值，不立即在此处应用应用
            tune_state["dyn_tcp_alive_limit"] = new_alive_limit
            cprint(f"   📊 PID 建议下一轮 TCP_ALIVE_LIMIT 调整为: {new_alive_limit} (当前: {cf_config.TCP_ALIVE_LIMIT}, 高层实际失败率: {high_level_fail*100:.1f}%)")

        # 记录调优历史
        history_entry = {
            "ts": int(time.time()),
            "health": round(health, 2),
            "survival_rate": round(survival_rate, 3),
            "median_ttfb": round(median_ttfb, 3),
            "jitter_pass_rate": round(jitter_pass_rate, 3),
            "tcp_workers": cf_config.MAX_TCP_WORKERS,
            "tcp_timeout": round(cf_config.TCP_TIMEOUT, 2),
            "trace_workers": cf_config.MAX_TRACE_WORKERS,
            "ttfb_workers": cf_config.MAX_TTFB_WORKERS,
            "ttfb_pool": cf_config.TTFB_POOL_LIMIT,
            "ttfb_max": round(cf_config.TTFB_MAX, 2),
            "tcp_alive_limit": cf_config.TCP_ALIVE_LIMIT
        }
        cf_autotune.record_history(tune_state, history_entry, cf_config.AUTOTUNE_HISTORY_MAX)

        if AUTOTUNE_ACTIVE:
            write_autotune_state(tune_state)

    cprint(f"   TTFB 阶段最终保留 {len(ttfb_passed)} 个节点进入下一轮测速")

    # ── 阶段 3.5：Range 请求支持检测 (v4.2 改为可选)
    range_check_enable = getattr(cf_config, "RANGE_CHECK_ENABLE", False)
    if range_check_enable:
        range_host = getattr(cf_config, "RANGE_CHECK_HOST", "speed.cloudflare.com")
        cprint(f"正在检测 Range 请求支持 (host={range_host})...")
        sem_range = asyncio.Semaphore(cf_config.MAX_TTFB_WORKERS)
        range_passed = []
        completed = 0
        total_range = len(ttfb_passed)

        async def check_range(node):
            nonlocal completed
            url = (f"{scheme_for(node[1])}://{range_host}:{node[1]}"
                   f"/__down?bytes=1048576")
            async with sem_range:
                try:
                    connector = aiohttp.TCPConnector(
                        resolver=SingleIPResolver(node[0]), ssl=False, force_close=True
                    )
                    async with aiohttp.ClientSession(
                        connector=connector,
                        timeout=aiohttp.ClientTimeout(total=cf_config.TRACE_TIMEOUT + 3)
                    ) as sess:
                        async with sess.get(
                            url,
                            headers={
                                "Host": range_host,
                                "User-Agent": cf_config.USER_AGENT,
                                "Range": "bytes=0-524287"
                            }
                        ) as r:
                            if r.status in (200, 206):
                                range_passed.append(node)
                except Exception:
                    pass
            completed += 1
            if completed % max(1, total_range // 10) == 0 or completed == total_range:
                cprint(f"\r   Range检测进度 {completed}/{total_range}，通过 {len(range_passed)}", log=False, end="", flush=True)

        await asyncio.gather(*[check_range(n) for n in ttfb_passed])
        print()
        if not range_passed:
            cprint("   ⚠️ 无节点通过 Range 检测，回退使用全部 TTFB 结果", level="warning")
            range_passed = ttfb_passed
    else:
        cprint("⏭️  Range 检测已关闭（RANGE_CHECK_ENABLE=False），跳过该阶段")
        range_passed = ttfb_passed


    # ── 阶段 4：下载测速
    speed_test_pool = sorted(range_passed, key=lambda x: x[4])[:cf_config.TTFB_POOL_LIMIT]
    cprint(f"正在进行下载测速 (按 TTFB 排序，共 {len(speed_test_pool)} 个 IP，并发 {cf_config.MAX_BW_WORKERS})...")
    bw_results = []
    sem_bw = asyncio.Semaphore(cf_config.MAX_BW_WORKERS)

    async def speed_test(node):
        url = (f"{scheme_for(node[1])}://speed.cloudflare.com:{node[1]}"
               f"/__down?bytes={cf_config.BW_MB * 1024 * 1024}")
        async with sem_bw:
            try:
                connector = aiohttp.TCPConnector(
                    resolver=SingleIPResolver(node[0]), ssl=False, force_close=True
                )
                async with aiohttp.ClientSession(
                    connector=connector,
                    timeout=aiohttp.ClientTimeout(total=cf_config.BW_TIMEOUT)
                ) as sess:
                    start = time.monotonic()
                    async with sess.get(
                        url, headers={"Host": "speed.cloudflare.com", "User-Agent": cf_config.USER_AGENT}
                    ) as r:
                        if r.status == 200:
                            size = 0
                            el = 0
                            TEST_DURATION = min(5.0, max(2.0, cf_config.BW_TIMEOUT - 1))
                            async for chunk in r.content.iter_chunked(65536):
                                size += len(chunk)
                                el = time.monotonic() - start
                                if el >= TEST_DURATION:
                                    break
                                if el > 0.5 and (size * 8) / (el * 1024 * 1024) >= cf_config.BW_EARLY_STOP_MBPS:
                                    break
                            if size > 0 and el > 0:
                                mbps = (size * 8) / (el * 1024 * 1024)
                                bw_results.append((*node, mbps))
                                cprint(f"   {node[0]}:{node[1]} [{node[3]}] {mbps:.1f} Mbps (TTFB: {node[4]*1000:.0f}ms)")
            except Exception:
                pass

    await asyncio.gather(*[speed_test(n) for n in speed_test_pool])

    # ── 阶段 5：综合评分排序

    bw_results.sort(key=compute_score, reverse=True)

    for n in bw_results:
        score = compute_score(n)
        record_result(
            memory_db,
            ip=n[0], port=n[1], cc=n[3],
            passed=True,
            score=score * 100,
            ttfb_ms=n[4] * 1000,
            mbps=n[5],
            range_ok=True
        )
    save_memory(memory_db)
    cprint(f"   记忆库已更新，当前 {len(memory_db)} 条记录")

        # ── 阶段 5 智能反馈调优 (v4.6 平滑版)
    target_pool = cf_config.TTFB_POOL_LIMIT
    current_limit = cf_config.MAX_TASK_LIMIT
    
    if ttfb_passed:
        top_10_ttfb = sum(n[4] for n in ttfb_passed[:10]) / min(10, len(ttfb_passed))
        
        # 趋势统计
        if len(ttfb_passed) > target_pool * 2 and top_10_ttfb < (cf_config.TTFB_TOP10_GOOD_MS / 1000.0):
            # 极品过剩，需要缩小初始探测上限
            tune_state["task_limit_down_streak"] = tune_state.get("task_limit_down_streak", 0) + 1
            tune_state["task_limit_up_streak"] = 0
        elif len(ttfb_passed) < target_pool or top_10_ttfb > (cf_config.TTFB_TOP10_POOR_MS / 1000.0):
            # 极品不足，需要增大初始探测上限
            tune_state["task_limit_up_streak"] = tune_state.get("task_limit_up_streak", 0) + 1
            tune_state["task_limit_down_streak"] = 0
        else:
            tune_state["task_limit_up_streak"] = 0
            tune_state["task_limit_down_streak"] = 0

        # 连续 N 轮同向才真正调优，防止单轮抖动
        target_limit = current_limit
        if tune_state.get("task_limit_down_streak", 0) >= cf_config.TASK_LIMIT_TREND_N:
            target_limit = max(cf_config.TASK_LIMIT_MIN, int(current_limit * 0.85))
            tune_state["task_limit_down_streak"] = 0
        elif tune_state.get("task_limit_up_streak", 0) >= cf_config.TASK_LIMIT_TREND_N:
            target_limit = min(cf_config.TASK_LIMIT_MAX, int(current_limit * 1.25))
            tune_state["task_limit_up_streak"] = 0

        if target_limit != current_limit:
            new_limit, limit_changed = cf_autotune.smooth_update(
                current_limit, target_limit,
                alpha=cf_config.AUTOTUNE_EMA_ALPHA,
                deadzone=cf_config.AUTOTUNE_DEADZONE,
                lo=cf_config.TASK_LIMIT_MIN,
                hi=cf_config.TASK_LIMIT_MAX,
                integer=True
            )
            if limit_changed:
                cprint(f"   📈 初始探测任务上限(MAX_TASK_LIMIT)调整为: {new_limit} (原: {current_limit})")
                cf_config.MAX_TASK_LIMIT = new_limit
                tune_state["dynamic_task_limit"] = new_limit

    if bw_results:
        top_3_mbps = sum(n[5] for n in bw_results[:3]) / min(3, len(bw_results))
        current_early_stop = cf_config.BW_EARLY_STOP_MBPS
        
        # ── 提前掐断带宽阈值 (Early Stop Mbps) EMA 调整
        target_early_stop = min(150.0, max(10.0, top_3_mbps * 0.8))
        new_early_stop, es_changed = cf_autotune.smooth_update(
            current_early_stop, target_early_stop,
            alpha=cf_config.AUTOTUNE_EMA_ALPHA,
            deadzone=cf_config.AUTOTUNE_DEADZONE,
            lo=10.0, hi=150.0
        )
        if es_changed:
            new_early_stop = round(new_early_stop, 1)
            cprint(f"   ⚡ 测速提前掐断线(BW_EARLY_STOP_MBPS)调整为: {new_early_stop} Mbps (原: {current_early_stop} Mbps)")
            cf_config.BW_EARLY_STOP_MBPS = new_early_stop
            tune_state["dynamic_early_stop"] = new_early_stop

        # ── 测速并发数 (MAX_BW_WORKERS) EMA 调整
        if top_3_mbps < 50.0:
            target_bw_workers = max(1, int(top_3_mbps / 8))
        else:
            target_bw_workers = min(20, getattr(cf_config, "MAX_BW_WORKERS", 10))
            
        current_bw_workers = cf_config.MAX_BW_WORKERS
        new_bw_workers, bw_workers_changed = cf_autotune.smooth_update(
            current_bw_workers, target_bw_workers,
            alpha=cf_config.AUTOTUNE_EMA_ALPHA,
            deadzone=cf_config.AUTOTUNE_DEADZONE,
            lo=1, hi=20, integer=True
        )
        if bw_workers_changed:
            cprint(f"   🚦 下载测速并发数调整为: {new_bw_workers} (原: {current_bw_workers})")
            cf_config.MAX_BW_WORKERS = new_bw_workers
            tune_state["dynamic_bw_workers"] = new_bw_workers

        # ── 测速文件大小 (BW_MB) EMA 调整
        if top_3_mbps > 100.0:
            target_bw_mb = 20
        elif top_3_mbps < 20.0:
            target_bw_mb = 5
        else:
            target_bw_mb = 10
            
        current_bw_mb = cf_config.BW_MB
        new_bw_mb, bw_mb_changed = cf_autotune.smooth_update(
            current_bw_mb, target_bw_mb,
            alpha=cf_config.AUTOTUNE_EMA_ALPHA,
            deadzone=cf_config.AUTOTUNE_DEADZONE,
            lo=5, hi=20, integer=True
        )
        if bw_mb_changed:
            cprint(f"   📦 下载测速文件大小调整为: {new_bw_mb}MB (原: {current_bw_mb}MB)")
            cf_config.BW_MB = new_bw_mb
            tune_state["dynamic_bw_mb"] = new_bw_mb

    # ── 均值回归：防止参数经过多轮后无限漂移到地板值
    if AUTOTUNE_ACTIVE:
        mr_strength = getattr(cf_config, 'MEAN_REVERSION_STRENGTH', 0.10)
        reverted = cf_autotune.mean_revert(tune_state, default_tune_state, mr_strength)
        if reverted > 0:
            cprint(f"   🔄 均值回归已应用：{reverted} 个参数向默认值回拉 {mr_strength*100:.0f}%")
        write_autotune_state(tune_state)

    cprint(f"\n正在将所有测速完成 of {len(bw_results)} 个节点分门别类归档...")
    archive_dir = os.path.join(OUT_DIR, "Tested_Nodes")
    os.makedirs(archive_dir, exist_ok=True)

    categorized_nodes = {}
    for n in bw_results:
        cc = n[3]
        if cc not in categorized_nodes:
            categorized_nodes[cc] = []
        categorized_nodes[cc].append(n)

    for cc, nodes in categorized_nodes.items():
        cc_file_path = os.path.join(archive_dir, f"tested_ips_{cc}.txt")
        with open(cc_file_path, "w", encoding="utf-8") as f:
            for i, n in enumerate(nodes, 1):
                ip_fmt = f"[{n[0]}]" if ":" in n[0] else n[0]
                port = n[1]
                ttfb = n[4] * 1000
                mbps = n[5]
                score = compute_score(n) * 100
                f.write(f"{ip_fmt}:{port}#{cc}-TTFB:{ttfb:.0f}ms-BW:{mbps:.1f}Mbps-Score:{score:.1f}\n")
        cprint(f"   -> 已归档 {len(nodes)} 个 [{cc}] 地区节点至 Tested_Nodes/tested_ips_{cc}.txt")

    # 智能多地区推送
    # 2026-11-11: 若记忆库融合开启，最终挑选按融合分排序而非纯本轮分
    from collections import defaultdict
    _min_score  = getattr(cf_config, "SMART_PUSH_MIN_SCORE",  35.0)
    _min_nodes  = getattr(cf_config, "SMART_PUSH_MIN_NODES",  2)
    _ips_per_cc = getattr(cf_config, "SMART_PUSH_IPS_PER_CC", 2)

    if len(bw_results) <= 5:
        _min_nodes  = 1
        _min_score  = max(10.0, _min_score * 0.4)
        cprint(f"   🆘 检测到测速节点极少 ({len(bw_results)} 个)，自动放宽推送门槛")

    cc_groups = defaultdict(list)
    for n in bw_results:
        cc_groups[n[3]].append(n)

    # 2026-11-11: 记忆库置信度融合排序——抗单轮 5s 采样方差
    # 最终分 = w_local × 本轮分 + w_memory × 记忆库置信度（passes≥MIN_RUNS 且未过期的节点才融合）
    w_local = float(getattr(cf_config, "PUSH_MEMORY_FUSE_W_LOCAL", 1.0))
    fuse_on = 0.0 < w_local < 1.0
    fused_scores = {}
    if fuse_on and bw_results:
        w_mem = 1.0 - w_local
        for n in bw_results:
            conf = get_node_confidence(memory_db, n[0], n[1])
            if conf is None:
                fused_scores[(n[0], n[1])] = compute_score(n)
            else:
                fused_scores[(n[0], n[1])] = w_local * compute_score(n) + w_mem * (conf / 100.0)
        fused_n = sum(1 for n in bw_results if get_node_confidence(memory_db, n[0], n[1]) is not None)
        cprint(f"   🧠 记忆库融合排序：{fused_n}/{len(bw_results)} 个节点有历史置信度（本轮 {w_local:.0%} + 记忆 {w_mem:.0%}）")

    def _rank_key(n):
        # 融合开启且有历史置信度 → 按融合分；否则纯本轮分
        return fused_scores.get((n[0], n[1]), compute_score(n)) if fuse_on else compute_score(n)

    # 2026-11-11: 地区分层 + 路由诊断（只决定准入与名额，不改评分口径与输出格式）
    # 旧逻辑用「地区最优节点均分 >= 30」一条绝对斜线门槛，实测把 38 个地区里的 29 个整体淘汰，
    # 且淘汰依据是「带宽×延迟」的斜线副产品，带宽低的地区一律死，与地区质量无关。
    tier_info = {}
    if getattr(cf_config, "REGION_TIER_ENABLE", False):
        tier_info = classify_region_tiers(cc_groups)
        # ── 诊断日志：分层 + 物理下限倍数 ──
        cprint(f"\n   🗺️  地区分层诊断（基线=本区最优 {int(getattr(cf_config, 'REGION_BASELINE_K', 3))} 节点均值）：")
        for cc, info in tier_info.items():
            d = info["diag"]
            ratio_txt = f"{d['ratio']:.0f}x/{d['floor_ms']:.0f}ms" if d.get("ratio") else "  -"
            cprint(f"      {cc:3s} n={info['n']:2d} 基线 {info['baseline_ms']:4.0f}ms  "
                   f"带中位 {info['bw_med']:5.1f}Mbps  物理倍数 {ratio_txt:>12s}  "
                   f"{d['label']:4s} -> {info['tier']}")
        cnt = {}
        for info in tier_info.values():
            cnt[info["tier"]] = cnt.get(info["tier"], 0) + 1
        cprint(f"      合计：T1 {cnt.get('T1',0)} / T2 {cnt.get('T2',0)} / "
               f"T3 {cnt.get('T3',0)} / DROP {cnt.get('DROP',0)}")
        save_region_baseline(tier_info)

    qualified_ccs = []
    for cc, nodes in cc_groups.items():
        sorted_nodes = sorted(nodes, key=_rank_key, reverse=True)
        top_nodes = sorted_nodes[:_ips_per_cc]
        top_avg = sum(compute_score(n) * 100 for n in top_nodes) / len(top_nodes)
        if tier_info:
            tier = tier_info.get(cc, {}).get("tier", "DROP")
            if tier == "DROP":
                cprint(f"   ⛔ [{cc}] 基线 {tier_info.get(cc, {}).get('baseline_ms', 0):.0f}ms 超 T3 上限，本轮不推送")
                continue
            if len(nodes) >= _min_nodes:
                qualified_ccs.append((cc, top_avg, sorted_nodes, tier))
        else:
            if len(nodes) >= _min_nodes and top_avg >= _min_score:
                qualified_ccs.append((cc, top_avg, sorted_nodes, None))

    if tier_info:
        # 层内按均分排序 + 每层配额（避免 T1 吃光名额，也让 T3 至少留下一个兜底）
        quota = {
            "T1": int(getattr(cf_config, "REGION_TIER_QUOTA_T1", 4)),
            "T2": int(getattr(cf_config, "REGION_TIER_QUOTA_T2", 3)),
            "T3": int(getattr(cf_config, "REGION_TIER_QUOTA_T3", 1)),
        }
        ordered = []
        for tier in ("T1", "T2", "T3"):
            same = sorted([q for q in qualified_ccs if q[3] == tier], key=lambda x: x[1], reverse=True)
            if len(same) > quota.get(tier, len(same)):
                cprint(f"   📋 {tier} 配额 {quota[tier]}，"
                       f"从 {len(same)} 个地区中取均分最高的 {quota[tier]} 个，"
                       f"落选: {', '.join(q[0] for q in same[quota[tier]:])}")
            ordered.extend(same[:quota.get(tier, len(same))])
        qualified_ccs = ordered
    else:
        qualified_ccs.sort(key=lambda x: x[1], reverse=True)

    # 2026-11-11: 仅 1 个地区达标时，把第二地区带进来（输出零冗余问题）
    # 分层模式下只在非 DROP 地区里挑，避免把 1600ms+ 的地区当兜底
    if len(qualified_ccs) == 1:
        fb_nodes = getattr(cf_config, "SMART_PUSH_MIN_NODES_FALLBACK", 2)
        second_best = []
        for cc, nodes in cc_groups.items():
            if any(cc == q[0] for q in qualified_ccs):
                continue
            if tier_info and tier_info.get(cc, {}).get("tier") == "DROP":
                continue
            if len(nodes) >= fb_nodes:
                second_best.append((cc,
                    sum(compute_score(n) * 100 for n in sorted(nodes, key=compute_score, reverse=True)[:_ips_per_cc]) / min(_ips_per_cc, len(nodes)),
                    sorted(nodes, key=compute_score, reverse=True),
                    (tier_info.get(cc, {}).get("tier") if tier_info else None)))
        if second_best:
            second_best.sort(key=lambda x: x[1], reverse=True)
            qualified_ccs.append(second_best[0])
            cprint(f"   🔗 单地区兜底：纳入第二地区 [{second_best[0][0]}] 均分 {second_best[0][1]:.1f}")

    final = []
    if qualified_ccs:
        cprint(f"\n   🌏 智能推送：{len(qualified_ccs)} 个地区达到推送门槛")
        for item in qualified_ccs:
            cc, avg, nodes = item[0], item[1], item[2]
            tier = item[3] if len(item) > 3 else None
            sorted_nodes = sorted(nodes, key=_rank_key, reverse=True)
            # 2026-11-11: 单节点绝对分门槛（地区基线合格 ≠ 每个节点合格）
            node_floor = float(getattr(cf_config, "PUSH_NODE_MIN_SCORE", 0) or 0)
            if node_floor > 0:
                passed_nodes = [n for n in sorted_nodes if compute_score(n) * 100 >= node_floor]
                if len(passed_nodes) < int(getattr(cf_config, "PUSH_NODE_MIN_SCORE_KEEP", 1)):
                    passed_nodes = sorted_nodes[:int(getattr(cf_config, "PUSH_NODE_MIN_SCORE_KEEP", 1))]
                weak = len(sorted_nodes) - len(passed_nodes)
                if weak:
                    cprint(f"      ↳ [{cc}] 单节点分门槛 {node_floor:.0f}：跳过 {weak} 个低分节点")
                sorted_nodes = passed_nodes
            picks = select_entry_ips_basket(sorted_nodes, _ips_per_cc)
            final.extend(picks)
            tier_txt = f" [{tier}]" if tier else ""
            cprint(f"   [{cc}]{tier_txt} 均分 {avg:.1f}，贡献 {len(picks)} 个 IP")
    else:
        cprint(f"   ⚠️ 无地区达到门槛（均分 < {_min_score} 或节点数 < {_min_nodes}），从全部测速结果兜底", level="warning")
        final = select_entry_ips_basket(sorted(bw_results, key=_rank_key, reverse=True), cf_config.BW_TOP_N)

    # 修复3：智能推送模式最终总数限制
    max_total = getattr(cf_config, "SMART_PUSH_MAX_TOTAL", cf_config.BW_TOP_N)
    final = final[:max_total]

    # 2026-11-11: 带宽硬下限——0.1Mbps 的"僵尸优选"不该出现在入口列表
    min_mbps = float(getattr(cf_config, "PUSH_MIN_MBPS", 0) or 0)
    if min_mbps > 0 and final:
        dropped = [n for n in final if n[5] < min_mbps]
        kept = [n for n in final if n[5] >= min_mbps]
        if dropped:
            cprint(f"   🩹 带宽硬下限 {min_mbps}Mbps：剔除 {len(dropped)} 个（" + ", ".join(f"{n[0]}" for n in dropped) + "）")
            # 从剩余测速结果回填，保持 /24 去重
            refill_pool = [x for x in bw_results if x[5] >= min_mbps and x not in kept]
            for x in sorted(refill_pool, key=_rank_key, reverse=True):
                if len(kept) >= max_total:
                    break
                prefix = '.'.join(x[0].split('.')[:3]) if ':' not in x[0] else x[0].rsplit(':', 4)[0]
                if any((('.'.join(k[0].split('.')[:3]) if ':' not in k[0] else k[0].rsplit(':', 4)[0]) == prefix) for k in kept):
                    continue
                kept.append(x)
            keep_floor = int(getattr(cf_config, "PUSH_MIN_MBPS_KEEP", 1))
            if not kept:
                best = max(final, key=compute_score)
                cprint(f"   ⚠️ 全部低于下限，兜底保留最高分节点 {best[0]} ({best[5]:.1f}Mbps)", level="warning")
                kept = [best]
            elif len(kept) < keep_floor:
                for n in sorted(dropped, key=compute_score, reverse=True):
                    kept.append(n)
                    if len(kept) >= keep_floor:
                        break
            final = kept[:max_total]

    # 修复2：备用池切片修正
    remaining_bw = [x for x in bw_results if x not in final]
    reserve_cands = remaining_bw[cf_config.RESERVE_CAND_START : cf_config.RESERVE_CAND_END]

    if not final:
        cprint("   没有测速结果，将使用 TTFB 延迟最低的前节点", level="warning")
        ttfb_sorted = sorted(ttfb_passed, key=lambda x: x[4])
        final = select_entry_ips_basket(ttfb_sorted, max_total)
        remaining_ttfb = [x for x in ttfb_sorted if x not in final]
        reserve_cands = remaining_ttfb[cf_config.RESERVE_CAND_START : cf_config.RESERVE_CAND_END]

    current_out_file = os.path.join(OUT_DIR, f"entry_ip_{net_name}.txt")
    current_nodes = []

    order_txt = "按分层(T1>T2>T3)与地区均分排序" if tier_info else "基于综合体验评分排序"
    cprint(f"\n前 {len(final)} 个 IP ({net_name}) [{order_txt}]")
    for i, n in enumerate(final, 1):
        ip_fmt = f"[{n[0]}]" if ":" in n[0] else n[0]
        node_str = f"{ip_fmt}:{n[1]}#{n[3]}-[{net_name}]"
        current_nodes.append(node_str)
        if len(n) == 6:
            score = compute_score(n) * 100
            cprint(f"  #{i:02d}  {node_str} - TTFB: {n[4]*1000:.0f}ms - {n[5]:.1f} Mbps (评分: {score:.1f})")
        else:
            cprint(f"  #{i:02d}  {node_str} - TTFB: {n[4]*1000:.0f}ms")

    with open(current_out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(current_nodes) + "\n")
    cprint(f"\n已保存至: {current_out_file}")
    save_json_result(final, current_out_file, net_name, compute_score)

    if reserve_cands:
        existing_reserve = {}
        if os.path.exists(RESERVE_FILE):
            for ip, port, cc in load_file_entries(RESERVE_FILE, with_cc=True):
                existing_reserve[f"{ip}:{port}"] = cc

        for n in reserve_cands:
            key = f"{n[0]}:{n[1]}"
            existing_reserve.pop(key, None)
            existing_reserve[key] = n[3]

        # 2026-11-11: IPv6 种子保底——v6 节点一周才轮到一次测速，不能被 v4 挤出备用池
        v6_keys = []
        if os.path.exists(V6_SEED_FILE):
            for line in open(V6_SEED_FILE, encoding="utf-8"):
                line = line.strip()
                if line and not line.startswith("#"):
                    v6_keys.append(line)

        def _split_host_port(key: str):
            m = re.match(r"^(.+):(\d{1,5})$", key)
            return (m.group(1), m.group(2)) if m else (key, None)

        reserve_list = list(existing_reserve.items())
        v6_in_reserve = {(_split_host_port(k)[0]) for k in existing_reserve if ":" in _split_host_port(k)[0]}
        for line in v6_keys:
            host, _port = _split_host_port(line.split("#")[0])
            cc = line.split("#", 1)[1] if "#" in line else ""
            if host not in v6_in_reserve:
                reserve_list.append((line.split("#")[0], cc))
        # v6 种子放最前（保证 -RESERVE_MAX 截断时永远在窗口内），去重保留最后出现
        head = [(k, cc) for k, cc in reserve_list if _split_host_port(k)[0] in v6_in_reserve or _split_host_port(k)[0] in {_split_host_port(l.split('#')[0])[0] for l in v6_keys}]
        tail = [(k, cc) for k, cc in reserve_list if (k, cc) not in head]
        dedup = {}
        for k, cc in tail:
            dedup[k] = cc
        tail = list(dedup.items())[-(cf_config.RESERVE_MAX - len(head)):]
        reserve_list = head + tail
        with open(RESERVE_FILE, "w", encoding="utf-8") as f:
            for ip_port, cc in reserve_list:
                f.write(f"{ip_port}#{cc}\n" if cc else f"{ip_port}\n")
        cprint(f"已更新历史备用池，当前容量: {len(reserve_list)} 个节点（含 {len(head)} 个 v6 保底）\n")

    # 修复6：网络合并与去重（过滤过期文件）
    merged_dict = {}
    cprint("正在合并网络数据...")
    ttl_days = getattr(cf_config, "OUTPUT_TTL_DAYS", 7)
    now = time.time()
    
    for filename in sorted(os.listdir(OUT_DIR)):
        if filename.startswith("entry_ip_") and filename.endswith(".txt"):
            filepath = os.path.join(OUT_DIR, filename)
            
            # 修复6：检查文件修改时间，过滤过期文件
            try:
                mtime = os.path.getmtime(filepath)
                if now - mtime > ttl_days * 86400:
                    cprint(f"   跳过过期文件: {filename} (超过 {ttl_days} 天)")
                    continue
            except Exception:
                pass
                
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        stripped = line.strip()
                        m = MERGE_LINE_RE.match(stripped)
                        if stripped and m:
                            port_val = int(m.group(1))
                            if 1 <= port_val <= 65535:
                                parts = stripped.split('-')
                                if len(parts) >= 2:
                                    base_part = "-".join(parts[:-1])
                                    net_tag = parts[-1]
                                    if base_part not in merged_dict:
                                        merged_dict[base_part] = set()
                                    merged_dict[base_part].add(net_tag)
            except Exception as e:
                logger.warning(f"读取文件失败 {filename}: {type(e).__name__}: {e}")

    merged_nodes = []
    for base_part, tags in merged_dict.items():
        joined_tags = "".join(sorted(list(tags)))
        if len(tags) > 1:
            merged_nodes.append(f"{base_part}-多网通吃{joined_tags}")
        else:
            merged_nodes.append(f"{base_part}-{joined_tags}")

    cprint(f"   已合并去重并标记出 {len(merged_nodes)} 个节点")

    # 修复7：保存本地合并文件
    if merged_nodes:
        merged_out_file = os.path.join(OUT_DIR, "ADD_merged.txt")
        with open(merged_out_file, "w", encoding="utf-8") as f:
            f.write("\n".join(merged_nodes) + "\n")
        cprint(f"   已保存合并结果: {merged_out_file}")

    if cf_config.WORKER_ENABLE and merged_nodes and not getattr(args, "json_only", False):
        await _push_worker_entry(merged_nodes)


async def _push_worker_entry(merged_nodes: list):
    cprint("正在推送到 Worker (ADD.txt)...")
    try:
        async with aiohttp.ClientSession(
            headers={"User-Agent": cf_config.USER_AGENT},
            timeout=aiohttp.ClientTimeout(total=15)
        ) as session:
            r = await session.post(
                f"{cf_config.WORKER_HOST.rstrip('/')}/login",
                data={"password": cf_config.WORKER_PASSWORD}
            )
            try:
                login_res = await r.json()
                if not login_res.get("success"):
                    cprint("   登录失败: 密码错误或 Worker 拒绝访问", level="warning")
                    return
            except Exception:
                cprint("   登录失败: 未获取到预期响应 (检查密码是否正确，或检查 WORKER_HOST 是否为 HTTPS)", level="warning")
                return

            custom_content = ""
            custom_file = os.path.join(SCRIPT_DIR, "custom_add.txt")
            if os.path.exists(custom_file):
                try:
                    with open(custom_file, "r", encoding="utf-8") as f:
                        content = f.read().strip()
                        if content:
                            custom_content = content + "\n"
                            cprint(f"   已加载本地自定义配置 ({custom_file})，将混合推送")
                except Exception as e:
                    cprint(f"   读取 custom_add.txt 失败: {e}，将仅推送本次测速结果", level="warning")

            add_content = custom_content + "\n".join(merged_nodes) + "\n"
            r2 = await session.post(
                f"{cf_config.WORKER_HOST.rstrip('/')}/admin/ADD.txt",
                data=add_content.encode("utf-8"),
                headers={"Content-Type": "text/plain;charset=utf-8"},
            )
            if r2.status == 200:
                cprint("   推送成功")
            else:
                cprint(f"   推送失败: {r2.status}", level="warning")
    except Exception as e:
        cprint(f"   推送错误: {type(e).__name__}: {e}", level="error")

async def _notify(message: str):
    if getattr(args, "no_notify", False):
        return

    async def _webhook():
        if not cf_config.NOTIFY_WEBHOOK_URL:
            return
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                await s.post(cf_config.NOTIFY_WEBHOOK_URL, json={"text": message, "msg_type": "text", "content": {"text": message}})
        except Exception as e:
            logger.debug(f"Webhook 通知失败: {e}")

    async def _telegram():
        if not (cf_config.NOTIFY_TG_TOKEN and cf_config.NOTIFY_TG_CHAT_ID):
            return
        try:
            url = f"https://api.telegram.org/bot{cf_config.NOTIFY_TG_TOKEN}/sendMessage"
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                await s.post(url, json={"chat_id": cf_config.NOTIFY_TG_CHAT_ID, "text": message, "parse_mode": "HTML"})
        except Exception as e:
            logger.debug(f"Telegram 通知失败: {e}")

    await asyncio.gather(_webhook(), _telegram())

async def main():
    cprint("=" * 54)
    cprint(f"CF Entrance Optimizer v{VERSION}")
    cprint("=" * 54)

    start_time = time.monotonic()
    
    # 运行动态爬虫更新配置
    try:
        cf_config.auto_update_config()
    except Exception as e:
        cprint(f"动态通讯录更新失败: {e}", level="warning")

    net_name = await get_current_net_name()
    cprint(f"当前网络环境: {net_name}")

    # 第二轮优化：IPv6 连通性检测
    if cf_config.IPV6_ENABLE:
        cprint("正在检测 IPv6 连通性...")
        ipv6_available = await check_ipv6_connectivity()
        if not ipv6_available:
            cf_config.IPV6_ENABLE = False

    memory_db = load_memory()
    pruned = prune_stale(memory_db)
    if pruned:
        cprint(f"已清理 {pruned} 条过期记录")
        # 修复8：清理后立即保存
        save_memory(memory_db)

    priority_ips = get_priority_candidates(memory_db, top_n=100)
    cidr_weights = get_cidr_weights(memory_db, cf_config.CF_CIDR_LIST)
    cprint(f"记忆库: {len(memory_db)} 条记录，{len(priority_ips)} 个优先候选")

    entrance_tasks = await collect_all_ips(
        load_premium=False, cidr_weights=cidr_weights, priority_ips=priority_ips
    )
    if entrance_tasks:
        await run_entrance_pipeline(entrance_tasks, net_name, memory_db, priority_ips=priority_ips)
    else:
        cprint("没有用于入口测试 of IP", level="warning")

    elapsed = time.monotonic() - start_time
    cprint(f"\n任务完成，耗时 {elapsed:.0f} 秒")
    cprint(f"日志文件: {LOG_FILE}\n")

    summary = f"✅ CF Entrance Optimizer v{VERSION} 完成\n网络: {net_name}\n耗时: {elapsed:.0f}s"
    await _notify(summary)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        cprint("\n已手动中断", level="warning")
        logger.warning("被用户中断")

