#!/usr/bin/env python3
"""
CF Optimizer v4.2 - 入口 IP 优选 + 代理 IP 纯净度检测
"""
import sys, os, time, re, json, socket, asyncio, random, ipaddress, subprocess, logging, importlib, argparse
from cf_memory import (
    load_memory, save_memory, record_result,
    get_priority_candidates, get_cidr_weights, prune_stale
)

# 强制控制台输出使用 UTF-8 编码，防止中文乱码
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

try:
    import cf_config
    from cf_config import (
        RUN_MODE, URL_SOURCES, EXCLUDE_COUNTRIES, PROXYIP_PREFER_COUNTRIES,
        PROXYIP_COUNT, MAX_TASK_LIMIT, RANDOM_SCAN_COUNT, MAX_TCP_WORKERS,
        MAX_TRACE_WORKERS, MAX_API_WORKERS, MAX_TTFB_WORKERS, MAX_BW_WORKERS,
        MAX_PURITY_WORKERS, TCP_TIMEOUT, TRACE_TIMEOUT, TTFB_MAX, BW_MB, BW_TIMEOUT,
        BW_EARLY_STOP_MBPS, WORKER_ENABLE, WORKER_HOST, WORKER_PASSWORD, USER_AGENT,
        CF_PORTS, CF_HTTPS_PORTS, CF_CIDR_LIST, CF_IPV6_CIDR_LIST, IPV6_ENABLE,
        TCP_ALIVE_LIMIT, TTFB_POOL_LIMIT, PROXY_API_LIMIT, PROXY_PURITY_LIMIT,
        BW_TOP_N, RESERVE_CAND_START, RESERVE_CAND_END, RESERVE_MAX, PREMIUM_MAX,
        IPAPI_MIN_INTERVAL, NOTIFY_WEBHOOK_URL, NOTIFY_TG_TOKEN, NOTIFY_TG_CHAT_ID
    )
except ImportError:
    print("错误: 当前目录下未找到 cf_config.py 配置文件。")
    sys.exit(1)

VERSION = "3.4-optimized-multinet"

SCRIPT_DIR     = os.path.dirname(os.path.abspath(__file__))

# 建立收纳目录
DATA_DIR = os.path.join(SCRIPT_DIR, "Data")
OUT_DIR  = os.path.join(SCRIPT_DIR, "Output")
LOG_DIR  = os.path.join(SCRIPT_DIR, "Logs")
for d in [DATA_DIR, OUT_DIR, LOG_DIR]:
    os.makedirs(d, exist_ok=True)

# 重新分配文件归属
LOG_FILE       = os.path.join(LOG_DIR, "cf_optimizer.log")
PROXY_OUT_FILE = os.path.join(OUT_DIR, "proxy_ip.txt")
PREMIUM_FILE   = os.path.join(DATA_DIR, "premium_proxy.txt")
RESERVE_FILE   = os.path.join(DATA_DIR, "reserve_ips.txt")
AUTOTUNE_FILE  = os.path.join(DATA_DIR, "autotune_state.json")

logger = logging.getLogger("CFOptimizer")
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
# 新增：智能调优状态机 (Auto-Tuning State)
# ==========================================
AUTOTUNE_FILE = os.path.join(DATA_DIR, "autotune_state.json")

def load_autotune_state():
    default_state = {
        "best_tcp_workers": getattr(cf_config, "MAX_TCP_WORKERS", 500),
        "dynamic_ttfb_max": getattr(cf_config, "TTFB_MAX", 0.8)
    }
    if os.path.exists(AUTOTUNE_FILE):
        try:
            with open(AUTOTUNE_FILE, "r", encoding="utf-8") as f:
                saved_state = json.load(f)
                default_state.update(saved_state)
        except Exception:
            pass
    return default_state

def save_autotune_state(state):
    with open(AUTOTUNE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

tune_state = load_autotune_state()
# 1. 防拥塞 & 降级
cf_config.MAX_TCP_WORKERS = tune_state.get("best_tcp_workers", getattr(cf_config, "MAX_TCP_WORKERS", 500))
cf_config.TTFB_MAX = tune_state.get("dynamic_ttfb_max", getattr(cf_config, "TTFB_MAX", 0.8))
# 2. 见好就收 & 量力而行
cf_config.MAX_TASK_LIMIT = tune_state.get("dynamic_task_limit", getattr(cf_config, "MAX_TASK_LIMIT", 2000))
cf_config.BW_EARLY_STOP_MBPS = tune_state.get("dynamic_early_stop", getattr(cf_config, "BW_EARLY_STOP_MBPS", 80.0))
# 3. 防挤兑 & 动态配重 & 算力节约
cf_config.MAX_BW_WORKERS = tune_state.get("dynamic_bw_workers", getattr(cf_config, "MAX_BW_WORKERS", 10))
cf_config.BW_MB = tune_state.get("dynamic_bw_mb", getattr(cf_config, "BW_MB", 10))
cf_config.RANDOM_SCAN_COUNT = tune_state.get("dynamic_random_scan", getattr(cf_config, "RANDOM_SCAN_COUNT", 10000))

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


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def ip_family(ip: str) -> int:
    try:
        addr = ipaddress.ip_address(ip)
        return socket.AF_INET6 if isinstance(addr, ipaddress.IPv6Address) else socket.AF_INET
    except ValueError:
        return socket.AF_INET


def cprint(msg, log=True, level="info", end="\n", flush=False):
    print(msg, end=end, flush=flush)
    if log and "\r" not in msg:
        clean_msg = re.sub(r'\033\[.*?m', '', msg).strip()
        getattr(logger, level)(clean_msg)


def check_env():
    cprint("正在检查运行环境...")
    logger.info(f"启动 CF Optimizer v{VERSION}，Python 版本 {sys.version.split()[0]}")
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


_ipapi_lock: "asyncio.Lock | None" = None
_ipapi_last_ts: float = 0.0

async def ipapi_throttle():
    global _ipapi_lock, _ipapi_last_ts
    if _ipapi_lock is None:
        _ipapi_lock = asyncio.Lock()
    async with _ipapi_lock:
        now = time.monotonic()
        wait = cf_config.IPAPI_MIN_INTERVAL - (now - _ipapi_last_ts)
        if wait > 0:
            await asyncio.sleep(wait)
        _ipapi_last_ts = time.monotonic()


async def get_current_net_name() -> str:
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            async with session.get("http://ip-api.com/json/?lang=zh-CN&fields=isp") as r:
                if r.status == 200:
                    isp = (await r.json()).get("isp", "Default").lower()

                    # 关键词模糊匹配，统一命名
                    if "mobile" in isp:
                        return "Mobile"  # 或者填 "移动"
                    elif "unicom" in isp:
                        return "Unicom"  # 或者填 "联通"
                    elif "telecom" in isp:
                        return "Telecom" # 或者填 "电信"
                    else:
                        # 如果是不认识的网，再走原来的老路
                        return re.sub(r'[^a-zA-Z0-9\u4e00-\u9fa5]', '_', (await r.json()).get("isp", "Default"))
    except Exception as e:
        logger.debug(f"get_current_net_name 失败: {type(e).__name__}: {e}")
    return "DefaultNet"


async def fetch_urls_classified(sources):
    premium_entries, normal_entries, bulk_entries = [], [], []

    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(headers={"User-Agent": cf_config.USER_AGENT}, timeout=timeout) as session:
        async def _fetch_one(src):
            url, quality, is_html, limit = (
                src["url"], src["quality"],
                src["type"] == "html", src.get("sample_limit", 0)
            )
            cprint(f"   [{quality.upper():7s}] 正在获取: {url}")
            local_entries = []
            local_seen = set()
            try:
                async with session.get(url) as r:
                    text = await r.text()
                    if is_html:
                        for ip in IPV4_RE.findall(text):
                            if not is_private_ip(ip) and ip not in local_seen:
                                local_seen.add(ip)
                                for p in cf_config.CF_PORTS:
                                    local_entries.append((ip, p))
                        if cf_config.IPV6_ENABLE:
                            for ip in IPV6_RE.findall(text):
                                try:
                                    ipaddress.IPv6Address(ip)
                                except ValueError:
                                    continue
                                if not is_private_ip(ip) and ip not in local_seen:
                                    local_seen.add(ip)
                                    local_entries.append((ip, 443))
                    else:
                        for line in text.splitlines():
                            raw = line.split('#')[0].strip()
                            m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$", raw)
                            if m and m.group(1) not in local_seen:
                                port = int(m.group(2))
                                if 1 <= port <= 65535:
                                    local_seen.add(m.group(1))
                                    local_entries.append((m.group(1), port))
                                continue
                            if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", raw) and raw not in local_seen:
                                local_seen.add(raw)
                                local_entries.append((raw, 443))
                                continue
                            if cf_config.IPV6_ENABLE:
                                m6 = re.match(r"^\[([^\]]+)\]:(\d{1,5})$", raw)
                                if m6:
                                    ip6, port = m6.group(1), int(m6.group(2))
                                elif IPV6_RE.fullmatch(raw):
                                    ip6, port = raw, 443
                                else:
                                    ip6 = None
                                if ip6 and ip6 not in local_seen:
                                    try:
                                        ipaddress.IPv6Address(ip6)
                                        local_seen.add(ip6)
                                        local_entries.append((ip6, port))
                                    except ValueError:
                                        pass

                    if limit > 0 and len(local_entries) > limit:
                        random.shuffle(local_entries)
                        local_entries = local_entries[:limit]
                    cprint(f"   [{quality.upper():7s}] 获取到 {len(local_entries)} 条: {url}")
            except Exception as e:
                logger.warning(f"获取失败 {url}: {type(e).__name__}: {e}")
            return quality, local_entries

        results = await asyncio.gather(*[_fetch_one(s) for s in sources])

    for quality, entries in results:
        if quality == "premium":
            premium_entries.extend(entries)
        elif quality == "normal":
            normal_entries.extend(entries)
        else:
            bulk_entries.extend(entries)

    return premium_entries, normal_entries, bulk_entries


async def collect_all_ips(load_premium: bool = False, cidr_weights: list = None, priority_ips: list = None) -> list:
    cprint("正在收集 IP 资源...")
    all_entries, seen_ips = [], set()

    if priority_ips:
        cprint(f"   已加载 {len(priority_ips)} 个记忆库优先节点")
        for ip, port, cc in priority_ips:
            if ip not in seen_ips:
                seen_ips.add(ip)
                all_entries.append((ip, port))

    for src_file in ([RESERVE_FILE, PREMIUM_FILE] if load_premium else [RESERVE_FILE]):
        nodes = load_file_entries(src_file, with_cc=True)
        for ip, port, cc in nodes:
            if ip not in seen_ips:
                seen_ips.add(ip)
                all_entries.append((ip, port))

    premium_e, normal_e, bulk_e = await fetch_urls_classified(cf_config.URL_SOURCES)

    for ip, port in premium_e:
        if ip not in seen_ips:
            seen_ips.add(ip)
            all_entries.append((ip, port))

    for ip, port in normal_e:
        if ip not in seen_ips:
            seen_ips.add(ip)
            all_entries.append((ip, port))

    # ====== 智能调节：算力节约 (动态盲扫数量) ======
    static_ips_count = len(seen_ips)
    current_random_scan = cf_config.RANDOM_SCAN_COUNT

    if static_ips_count > 1000:
        # 静态源抓取极好，削减盲扫数量，节约 CPU 算力
        actual_scan_count = max(1000, int(current_random_scan * 0.2))
        cprint(f"   💡 静态源极充沛 ({static_ips_count} 个)，自动减少盲扫数量至 {actual_scan_count}")
        tune_state["dynamic_random_scan"] = actual_scan_count
    elif static_ips_count < 200:
        # 静态源大面积失效，拉满盲扫数量保底
        actual_scan_count = min(30000, current_random_scan * 2)
        cprint(f"   ⚠️ 静态源极少 ({static_ips_count} 个)，自动增加盲扫数量至 {actual_scan_count}")
        tune_state["dynamic_random_scan"] = actual_scan_count
    else:
        actual_scan_count = current_random_scan

    save_autotune_state(tune_state)
    # ==============================================

    rand_ips = generate_random_ips(actual_scan_count, weights=cidr_weights, ipv6=False)
    if cf_config.IPV6_ENABLE:
        rand_ips += generate_random_ips(actual_scan_count // 2, ipv6=True)

    # 🆕 v4.2 修复：把随机生成的盲扫 IP 加入任务池（原代码因 ip 未定义会触发 NameError）
    for ip, port in rand_ips:
        if ip not in seen_ips:
            seen_ips.add(ip)
            all_entries.append((ip, port))

    tasks = []
    for ip, port in all_entries:
        for p in ([port] if port in cf_config.CF_PORTS else cf_config.CF_PORTS):
            tasks.append((ip, p))

    tasks = list(dict.fromkeys(tasks))
    tasks = tasks[:cf_config.MAX_TASK_LIMIT]
    cprint(f"   共收集到 {len(tasks)} 个 IP:Port 用于测试")
    return tasks


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
    cidr_seen = {}
    selected = []

    for item in results:
        ip = item[0]
        if ":" in ip:
            try:
                prefix = str(ipaddress.IPv6Network(f"{ip}/48", strict=False).network_address)
            except ValueError:
                prefix = ip
        else:
            prefix = ".".join(ip.split(".")[:2])

        if prefix in cidr_seen:
            continue

        cidr_seen[prefix] = True
        selected.append(item)
        if len(selected) >= top_n:
            break

    return selected


def select_with_diversity(nodes: list, top_n: int, per_cc: int = 2) -> list:
    """地区多样性挑选（v4.2 新增，替代 VIP 功能的"防扎堆"作用）。

    与 select_entry_ips_basket 的区别：
      - select_entry_ips_basket: 按 CIDR 前缀去重（/24 或 /48）
      - select_with_diversity: 按国家去重（每个国家最多 per_cc 个）

    用途：保证最终输出的 top_n 个 IP 来自多个不同国家，避免单国扎堆。
    """
    if not nodes:
        return []

    from collections import defaultdict

    # 1. 按国家分组
    cc_groups = defaultdict(list)
    for n in nodes:
        cc = n[3] if len(n) > 3 else "XX"
        cc_groups[cc].append(n)

    # 2. 每个国家按评分降序排，取前 per_cc 个
    selected = []
    for cc, group in cc_groups.items():
        # 检查是否已有完整测速数据（6 元组）来决定是否排序
        if len(group[0]) > 5:
            try:
                group_sorted = sorted(group, key=compute_score, reverse=True)
            except Exception:
                group_sorted = group
        else:
            group_sorted = sorted(group, key=lambda x: x[4])  # 按 TTFB 排
        selected.extend(group_sorted[:per_cc])

    # 3. 全部塞进篮子后再做 CIDR 去重
    final = select_entry_ips_basket(selected, top_n)
    return final


async def run_entrance_pipeline(tasks: list, net_name: str, memory_db: dict):
    cprint("\n" + "=" * 54)
    cprint("开始运行入口 IP 测速")
    cprint("=" * 54)

    # ── 阶段 1：TCP 连通性探测
    cprint(f"TCP 探测中 (共 {len(tasks)} 个，并发 {cf_config.MAX_TCP_WORKERS})...")
    sem = asyncio.Semaphore(cf_config.MAX_TCP_WORKERS)
    best: dict[str, tuple] = {}
    completed = 0
    alive_count = 0
    total = len(tasks)

    async def probe(ip, port):
        nonlocal completed, alive_count
        lat = None
        async with sem:
            try:
                start = time.monotonic()
                _, w = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=cf_config.TCP_TIMEOUT
                )
                lat = time.monotonic() - start
                alive_count += 1
            except Exception as e:
                logger.debug(f"TCP probe {ip}:{port} 失败: {type(e).__name__}: {e}")
            else:
                try:
                    w.close()
                    await w.wait_closed()
                except Exception:
                    pass
        completed += 1
        if completed % max(1, total // 20) == 0 or completed == total:
            cprint(f"\r   进度 {completed}/{total}，存活 {alive_count}", log=False, end="", flush=True)
        return ip, port, lat

    res = await asyncio.gather(*[probe(i, p) for i, p in tasks])
    print()

    # ====== 智能调节：TCP 并发拥塞控制 (防炸路由版) ======
    survival_rate = alive_count / max(1, total)
    current_workers = cf_config.MAX_TCP_WORKERS

    # 提高敏感度：存活率低于 8% 就说明路由器开始丢包了，果断降速
    if survival_rate < 0.08:
        new_workers = max(100, int(current_workers * 0.6))
        cprint(f"   ⚠️ 存活率偏低 ({survival_rate:.1%})，触发防拥塞保护，下次并发降至 {new_workers}", level="warning")
    # 设置合理上限：即使网络再好，家用环境最高也不要超过 400 并发，稳才是王道
    elif survival_rate > 0.20 and current_workers < 400:
        new_workers = min(400, current_workers + 30)
        if new_workers > current_workers:
            cprint(f"   🚀 网络游刃有余，下次并发温和提升至 {new_workers}")
    else:
        new_workers = current_workers

    if new_workers != current_workers:
        tune_state["best_tcp_workers"] = new_workers
        save_autotune_state(tune_state)
    # =========================================

    for r in res:
        if r and r[2] is not None:
            if r[0] not in best or r[2] < best[r[0]][1]:
                best[r[0]] = (r[1], r[2])

    alive = sorted(
        [(ip, p, lat) for ip, (p, lat) in best.items()],
        key=lambda x: x[2]
    )[:cf_config.TCP_ALIVE_LIMIT]
    cprint(f"   发现 {len(alive)} 个存活节点")

    if not alive:
        logger.warning("TCP 探测后没有存活节点")
        return

    # ── 阶段 2：/trace 获取国家代码
    cprint("正在检测节点所在国家/地区...")
    sem_tr = asyncio.Semaphore(cf_config.MAX_TRACE_WORKERS)
    tagged = []
    completed = 0
    total_alive = len(alive)

    async def trace(node):
        nonlocal completed
        host_ip = f"[{node[0]}]" if ":" in node[0] else node[0]
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
                    async with sess.get(
                        url, headers={"Host": "cp.cloudflare.com", "User-Agent": cf_config.USER_AGENT}
                    ) as r:
                        if r.status == 200:
                            for line in (await r.text()).splitlines():
                                if line.startswith("loc="):
                                    cc = line.split("=")[1].strip().upper()
                                    # 第一重过滤：绝不能在黑名单中
                                    if cc not in cf_config.EXCLUDE_COUNTRIES:
                                        # 第二重过滤：如果开启了白名单，必须在白名单中
                                        if hasattr(cf_config, "ONLY_COUNTRIES") and cf_config.ONLY_COUNTRIES:
                                            if cc in cf_config.ONLY_COUNTRIES:
                                                tagged.append((*node, cc))
                                        else:
                                            # 如果白名单是空的 set()，或者没写白名单，则按照旧逻辑直接放行
                                            tagged.append((*node, cc))
                                    break
            except Exception as e:
                logger.debug(f"trace {node[0]}:{node[1]} 失败: {type(e).__name__}: {e}")
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

    async def measure_ttfb(node):
        nonlocal completed
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
            except Exception as e:
                pass

        if len(samples) >= 2:
            samples.sort()
            median_ttfb = samples[len(samples) // 2]
            jitter = samples[-1] - samples[0]
            # 放宽一点抖动容忍度，不再这里直接淘汰高延迟节点，全部先存下来
            if jitter <= 0.2:
                ttfb_passed.append((*node, median_ttfb))
        elif len(samples) == 1:
            ttfb_passed.append((*node, samples[0]))

        completed += 1
        cprint(f"\r   TTFB 测试 {completed}/{total_ttfb}，收集到 {len(ttfb_passed)} 个有效回复", log=False, end="", flush=True)

    await asyncio.gather(*[measure_ttfb(n) for n in tagged])
    print()

    # ====== 智能调节：动态延迟阈值降级 ======
    if ttfb_passed:
        ttfb_passed.sort(key=lambda x: x[4]) # 按延迟从小到大排
        # 严格符合当前设定的节点
        strict_passed = [n for n in ttfb_passed if n[4] < cf_config.TTFB_MAX]

        target_pool_size = getattr(cf_config, "TTFB_POOL_LIMIT", 80)

        if len(strict_passed) >= target_pool_size:
            # 优质节点充足，尝试收紧标准（v4.2: 最低 0.7s，更宽容）
            tune_state["dynamic_ttfb_max"] = max(0.7, cf_config.TTFB_MAX - 0.1)
            ttfb_passed = strict_passed
            cprint(f"   🎯 优质节点充足，标准自动收紧至 {tune_state['dynamic_ttfb_max']:.2f}s")
        else:
            # 优质节点不够，放宽标准，矮子里拔将军
            worst_ttfb = ttfb_passed[:target_pool_size][-1][4]
            new_max = min(2.5, max(cf_config.TTFB_MAX + 0.2, worst_ttfb))
            if new_max > cf_config.TTFB_MAX:
                tune_state["dynamic_ttfb_max"] = new_max
                cprint(f"   ⚠️ 网络拥堵，合格节点不足，自动放宽延迟阈值至 {new_max:.2f}s", level="warning")

            # 强行截取前 N 个最好的节点继续测试，无视绝对延迟大小
            ttfb_passed = ttfb_passed[:target_pool_size]

        save_autotune_state(tune_state)
        cf_config.TTFB_MAX = tune_state["dynamic_ttfb_max"]

    cprint(f"   TTFB 阶段最终保留 {len(ttfb_passed)} 个节点进入下一轮测速")
    # ========================================

    if not ttfb_passed:
        return

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
            # 用 speed.cloudflare.com 测 Range，比 cdnjs 更通用
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
                            # 放宽判定：206 (部分内容) 或 200 (整段) 都算通过
                            if r.status in (200, 206):
                                range_passed.append(node)
                except Exception as e:
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
        # v4.2 默认路径：跳过 Range 检测
        cprint("⏭️  Range 检测已关闭（RANGE_CHECK_ENABLE=False），跳过该阶段")
        range_passed = ttfb_passed

    # ── 阶段 4：固定时长下载测速 (v4.2 移除 VIP 拆分，简化为按 TTFB 取前 N)
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
            except Exception as e:
                logger.debug(f"speed_test {node[0]}:{node[1]} 失败: {type(e).__name__}: {e}")

    await asyncio.gather(*[speed_test(n) for n in speed_test_pool])

    # ── 阶段 5：综合评分排序
    def compute_score(node):
        ttfb_ms = node[4] * 1000
        mbps = node[5]
        TTFB_WEIGHT = 0.6
        BW_WEIGHT = 0.4
        MAX_TTFB_MS = cf_config.TTFB_MAX * 1000 if cf_config.TTFB_MAX else 500.0
        MAX_BPS = 150.0
        latency_score = max(0.0, 1.0 - (ttfb_ms / MAX_TTFB_MS))
        bw_score = min(mbps / MAX_BPS, 1.0)
        return TTFB_WEIGHT * latency_score + BW_WEIGHT * bw_score

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

    # ====== 智能调节：完全体复盘算法 ======
    # 1. 动态任务截断 (省时间 -> 质量与数量双重认证机制)
    target_pool = getattr(cf_config, "TTFB_POOL_LIMIT", 80)
    current_limit = cf_config.MAX_TASK_LIMIT

    if ttfb_passed:
        # 取前 10 名最优秀的节点计算平均延迟，作为当前批次的"极品度"指标
        top_10_ttfb = sum(n[4] for n in ttfb_passed[:10]) / min(10, len(ttfb_passed))

        # 降级条件：数量极其充足 (>160) 【并且】 头部节点质量极高 (Top10均延迟低于0.18秒)
        if len(ttfb_passed) > target_pool * 2 and top_10_ttfb < 0.18:
            new_limit = max(1500, int(current_limit * 0.85)) # 降级变得极其保守，保底扫 1500 个
            if new_limit < current_limit:
                tune_state["dynamic_task_limit"] = new_limit
                cprint(f"   📉 极品节点储备过剩 (Top10均延迟 {top_10_ttfb*1000:.0f}ms)，适度减少初始撒网量至 {new_limit}")

        # 升级条件：数量不够，【或者】 头部质量拉胯 (比如最好的10个节点平均延迟都超过 250ms)
        elif len(ttfb_passed) < target_pool or top_10_ttfb > 0.25:
            new_limit = min(5000, int(current_limit * 1.25)) # 每次扩充 25% 的扫描量
            if new_limit > current_limit:
                tune_state["dynamic_task_limit"] = new_limit
                reason = "合格节点不足" if len(ttfb_passed) < target_pool else f"头部极品度欠佳 (Top10均延迟 {top_10_ttfb*1000:.0f}ms)"
                cprint(f"   📈 {reason}，扩大撒网范围至 {new_limit}，继续大浪淘沙")

    if bw_results:
        # 取前 3 名均速作为当前环境的极限带宽参考
        top_3_mbps = sum(n[5] for n in bw_results[:3]) / min(3, len(bw_results))

        # 2. 动态测速掐断线 (量力而行)
        current_early_stop = cf_config.BW_EARLY_STOP_MBPS
        new_early_stop = min(150.0, max(10.0, top_3_mbps * 0.8))
        if abs(new_early_stop - current_early_stop) / current_early_stop > 0.15:
            tune_state["dynamic_early_stop"] = round(new_early_stop, 1)
            cprint(f"   ⚡ 根据极限带宽，测速提前掐断线调整为 {tune_state['dynamic_early_stop']} Mbps")

        # 3. 动态测速并发数 (防挤兑)
        if top_3_mbps < 50.0:
            # 宽带太小，降低并发，保证每个连接至少分到一点速度
            new_bw_workers = max(1, int(top_3_mbps / 8))
        else:
            # 宽带充裕，放开并发
            new_bw_workers = min(20, getattr(cf_config, "MAX_BW_WORKERS", 10))

        if new_bw_workers != tune_state.get("dynamic_bw_workers", getattr(cf_config, "MAX_BW_WORKERS", 10)):
            tune_state["dynamic_bw_workers"] = new_bw_workers
            cprint(f"   🚦 避免带宽挤兑，下次测速并发数调整为 {new_bw_workers}")

        # 4. 动态测速包大小 (动态配重)
        if top_3_mbps > 100.0:
            new_bw_mb = 20 # 百兆以上用 20MB 压测持续性
        elif top_3_mbps < 20.0:
            new_bw_mb = 5  # 二十兆以下用 5MB 快速过检
        else:
            new_bw_mb = 10

        if new_bw_mb != tune_state.get("dynamic_bw_mb", getattr(cf_config, "BW_MB", 10)):
            tune_state["dynamic_bw_mb"] = new_bw_mb
            cprint(f"   📦 根据均速分布，下次测速文件大小调整为 {new_bw_mb} MB")

    save_autotune_state(tune_state)
    # ================================================
    cprint(f"\n正在将所有测速完成的 {len(bw_results)} 个节点分门别类归档...")

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
    # ===================================================

    # === 智能多地区推送：自动按均分筛选值得推送的地区 ===
    from collections import defaultdict
    _min_score  = getattr(cf_config, "SMART_PUSH_MIN_SCORE",  35.0)
    _min_nodes  = getattr(cf_config, "SMART_PUSH_MIN_NODES",  2)
    _ips_per_cc = getattr(cf_config, "SMART_PUSH_IPS_PER_CC", 2)

    # 🆕 v4.2: 节点稀疏时的兜底降级 —— 少于 5 个节点时降低门槛抢救一下
    if len(bw_results) <= 5:
        _min_nodes  = 1
        _min_score  = max(10.0, _min_score * 0.4)
        cprint(f"   🆘 检测到测速节点极少 ({len(bw_results)} 个)，自动放宽推送门槛")

    cc_groups = defaultdict(list)
    for n in bw_results:
        cc_groups[n[3]].append(n)

    qualified_ccs = []
    for cc, nodes in cc_groups.items():
        # 1. 先按分数从高到低排序
        sorted_nodes = sorted(nodes, key=compute_score, reverse=True)

        # 2. 截取前 N 个需要推送的节点
        top_nodes = sorted_nodes[:_ips_per_cc]

        # 3. 只计算头部精锐节点的平均分
        top_avg = sum(compute_score(n) * 100 for n in top_nodes) / len(top_nodes)

        # 4. 判断头部平均分是否达标
        if len(nodes) >= _min_nodes and top_avg >= _min_score:
            qualified_ccs.append((cc, top_avg, sorted_nodes))
    qualified_ccs.sort(key=lambda x: x[1], reverse=True)

    final = []
    if qualified_ccs:
        cprint(f"\n   🌏 智能推送：{len(qualified_ccs)} 个地区达到推送门槛")
        for cc, avg, nodes in qualified_ccs:
            sorted_nodes = sorted(nodes, key=compute_score, reverse=True)
            # 🆕 v4.2: 用 select_with_diversity 替代原 select_entry_ips_basket，支持地区配额
            picks = select_with_diversity(sorted_nodes, _ips_per_cc, per_cc=2)
            final.extend(picks)
            cprint(f"   [{cc}] 均分 {avg:.1f}，贡献 {len(picks)} 个 IP")
    else:
        # 🆕 v4.2: 兜底 —— 移除 VIP 优先逻辑，直接从全量测速结果中按评分 + CIDR 去重挑选
        cprint(f"   ⚠️ 无地区达到门槛（均分 < {_min_score} 或节点数 < {_min_nodes}），从全部测速结果兜底", level="warning")
        final = select_entry_ips_basket(bw_results, cf_config.BW_TOP_N)
    # ====================================
    # ====================================

    remaining_bw = [x for x in bw_results if x not in final]
    reserve_cands = remaining_bw[:(cf_config.RESERVE_CAND_END - cf_config.RESERVE_CAND_START)]

    if not final:
        cprint("   没有测速结果，将使用 TTFB 延迟最低的前节点", level="warning")
        ttfb_sorted = sorted(ttfb_passed, key=lambda x: x[4])
        final = select_entry_ips_basket(ttfb_sorted, cf_config.BW_TOP_N)
        remaining_ttfb = [x for x in ttfb_sorted if x not in final]
        reserve_cands = remaining_ttfb[:(cf_config.RESERVE_CAND_END - cf_config.RESERVE_CAND_START)]

    current_out_file = os.path.join(OUT_DIR, f"entry_ip_{net_name}.txt")
    current_nodes = []

    cprint(f"\n前 {len(final)} 个 IP ({net_name}) [基于综合体验评分排序]")
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
        existing_reserve: dict[str, str] = {}
        if os.path.exists(RESERVE_FILE):
            for ip, port, cc in load_file_entries(RESERVE_FILE, with_cc=True):
                existing_reserve[f"{ip}:{port}"] = cc

        for n in reserve_cands:
            key = f"{n[0]}:{n[1]}"
            existing_reserve.pop(key, None)
            existing_reserve[key] = n[3]

        reserve_list = list(existing_reserve.items())[-cf_config.RESERVE_MAX:]
        with open(RESERVE_FILE, "w", encoding="utf-8") as f:
            for ip_port, cc in reserve_list:
                f.write(f"{ip_port}#{cc}\n")
        cprint(f"已更新历史备用池，当前容量: {len(reserve_list)} 个节点\n")

    # ==================== 核心更新：多网环境标签合并与智能分组去重 ====================
    merged_dict = {}
    cprint("正在合并网络数据...")
    for filename in sorted(os.listdir(OUT_DIR)):
        if filename.startswith("entry_ip_") and filename.endswith(".txt"):
            filepath = os.path.join(OUT_DIR, filename)
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
                                    base_part = "-".join(parts[:-1])  # 提取前半段 (例如 IP:Port#CC)
                                    net_tag = parts[-1]               # 提取后半段网络标签 (例如 [Telecom])

                                    if base_part not in merged_dict:
                                        merged_dict[base_part] = set()
                                    merged_dict[base_part].add(net_tag)
            except Exception as e:
                logger.warning(f"读取文件失败 {filename}: {type(e).__name__}: {e}")

    merged_nodes = []
    for base_part, tags in merged_dict.items():
        joined_tags = "".join(sorted(list(tags)))

        if len(tags) > 1:
            # 双网或三网都表现极佳，合并为单条并标注高亮后缀
            merged_nodes.append(f"{base_part}-多网通吃{joined_tags}")
        else:
            merged_nodes.append(f"{base_part}-{joined_tags}")

    cprint(f"   已合并去重并标记出 {len(merged_nodes)} 个节点")
    # ==============================================================================

    if cf_config.WORKER_ENABLE and merged_nodes and not getattr(args, "json_only", False):
        await _push_worker_entry(merged_nodes)
async def run_proxy_pipeline(tasks: list, memory_db: dict):
    cprint("\n" + "=" * 54)
    cprint("开始运行代理 IP 纯净度检测")
    cprint("=" * 54)

    cprint("连通性检测中...")
    sem_tr = asyncio.Semaphore(cf_config.MAX_TRACE_WORKERS)
    tagged = []
    completed = 0
    total_tasks = len(tasks)

    async def basic_probe(ip, port):
        nonlocal completed
        url = f"{scheme_for(port)}://cp.cloudflare.com:{port}/cdn-cgi/trace"
        async with sem_tr:
            try:
                connector = aiohttp.TCPConnector(
                    resolver=SingleIPResolver(ip), ssl=False, force_close=True
                )
                async with aiohttp.ClientSession(
                    connector=connector,
                    timeout=aiohttp.ClientTimeout(total=cf_config.TRACE_TIMEOUT)
                ) as sess:
                    async with sess.get(
                        url, headers={"Host": "cp.cloudflare.com", "User-Agent": cf_config.USER_AGENT}
                    ) as r:
                        if r.status == 200:
                            for line in (await r.text()).splitlines():
                                if line.startswith("loc="):
                                    cc = line.split("=")[1].strip().upper()
                                    if cc not in cf_config.EXCLUDE_COUNTRIES:
                                        tagged.append((ip, port, cc))
                                    break
            except Exception as e:
                pass
        completed += 1
        if completed % max(1, total_tasks // 20) == 0 or completed == total_tasks:
            cprint(f"\r   进度 {completed}/{total_tasks}，存活 {len(tagged)}", log=False, end="", flush=True)

    await asyncio.gather(*[basic_probe(i, p) for i, p in tasks])
    print()
    cprint(f"   发现 {len(tagged)} 个节点")
    if not tagged:
        return

    cprint("正在验证代理能力...")
    proxy_capable = []
    sem_api = asyncio.Semaphore(cf_config.MAX_API_WORKERS)
    check_pool = tagged[:cf_config.PROXY_API_LIMIT]
    completed = 0
    total_api = len(check_pool)

    async with aiohttp.ClientSession(
        headers={"User-Agent": cf_config.USER_AGENT},
        timeout=aiohttp.ClientTimeout(total=6)
    ) as api_sess:
        async def check_api(node):
            nonlocal completed
            url = f"https://api.check.proxyip.cmliussss.net/check?proxyip={node[0]}:{node[1]}"
            async with sem_api:
                try:
                    async with api_sess.get(url, ssl=False) as r:
                        if r.status == 200 and (await r.json()).get("success") is True:
                            proxy_capable.append(node)
                except Exception as e:
                    pass
            completed += 1
            if completed % max(1, total_api // 10) == 0 or completed == total_api:
                cprint(f"\r   验证进度 {completed}/{total_api}，通过 {len(proxy_capable)}", log=False, end="", flush=True)

        await asyncio.gather(*[check_api(n) for n in check_pool])
    print()
    cprint(f"   通过 {len(proxy_capable)} 个节点")

    cprint("纯净度检测中...")
    pure_nodes = []
    sem_pure = asyncio.Semaphore(cf_config.MAX_PURITY_WORKERS)
    pure_pool = proxy_capable[:cf_config.PROXY_PURITY_LIMIT]
    completed = 0
    total_pure = len(pure_pool)

    async with aiohttp.ClientSession(
        headers={"User-Agent": cf_config.USER_AGENT},
        timeout=aiohttp.ClientTimeout(total=5)
    ) as pure_sess:
        async def check_purity(node):
            nonlocal completed
            url = f"http://ip-api.com/json/{node[0]}?fields=status,mobile,proxy,hosting"
            await ipapi_throttle()
            async with sem_pure:
                try:
                    async with pure_sess.get(url) as r:
                        if r.status == 200:
                            data = await r.json()
                            if data.get("status") == "success" and not data.get("proxy"):
                                pure_nodes.append(node)
                                cprint(f"\n   有效 {node[0]}:{node[1]} [{node[2]}]")
                except Exception as e:
                    pass
            completed += 1
            cprint(f"\r   纯净度检测进度 {completed}/{total_pure}", log=False, end="", flush=True)

        await asyncio.gather(*[check_purity(n) for n in pure_pool])
    print()

    final = pure_nodes if pure_nodes else proxy_capable[:cf_config.BW_TOP_N]
    if not pure_nodes:
        cprint("   纯净度检测无通过节点，使用 API 验证结果", level="warning")
    else:
        alive_dict = {f"{n[0]}:{n[1]}": n[2] for n in tagged}
        new_pure_dict = {f"{n[0]}:{n[1]}": n[2] for n in pure_nodes}
        vault: dict[str, str] = {}
        for ip, port, cc in load_file_entries(PREMIUM_FILE, with_cc=True):
            key = f"{ip}:{port}"
            if key in alive_dict:
                vault[key] = cc
        for key, cc in new_pure_dict.items():
            vault[key] = cc
        with open(PREMIUM_FILE, "w", encoding="utf-8") as f:
            for ip_port, cc in list(vault.items())[:cf_config.PREMIUM_MAX]:
                f.write(f"{ip_port}#{cc}\n")
        cprint(f"白名单已保存: {min(len(vault), cf_config.PREMIUM_MAX)} 个节点")

    for node in final:
        record_result(
            memory_db,
            ip=node[0], port=node[1], cc=node[2],
            passed=True, score=60.0,
            stage="full"
        )
    save_memory(memory_db)

    cprint(f"\n前 {len(final)} 个代理 IP")
    with open(PROXY_OUT_FILE, "w", encoding="utf-8") as f:
        for i, n in enumerate(final, 1):
            ip_fmt = f"[{n[0]}]" if ":" in n[0] else n[0]
            cprint(f"  #{i:02d}  {ip_fmt}:{n[1]} [{n[2]}]")
            f.write(f"{ip_fmt}:{n[1]}#{n[2]}\n")
    cprint(f"\n已保存至: {PROXY_OUT_FILE}")

    if cf_config.WORKER_ENABLE and final and not getattr(args, "json_only", False):
        await _push_worker_proxy(final)


async def _push_worker_entry(merged_nodes: list):
    cprint("正在推送到 Worker (ADD.txt)...")
    try:
        async with aiohttp.ClientSession(
            headers={"User-Agent": cf_config.USER_AGENT},
            timeout=aiohttp.ClientTimeout(total=15)
        ) as session:
            # 登录逻辑保持不变
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

            # ==========================================
            # 读取本地自定义静态文件 (custom_add.txt)
            # ==========================================
            custom_content = ""
            custom_file = os.path.join(SCRIPT_DIR, "custom_add.txt")
            if os.path.exists(custom_file):
                try:
                    with open(custom_file, "r", encoding="utf-8") as f:
                        # 读取内容并去除首尾空白字符
                        content = f.read().strip()
                        if content:
                            custom_content = content + "\n"
                            cprint(f"   已加载本地自定义配置 ({custom_file})，将混合推送")
                except Exception as e:
                    cprint(f"   读取 custom_add.txt 失败: {e}，将仅推送本次测速结果", level="warning")

            # 将静态内容与本次脚本跑出来的优选 IP 合并
            # 注意：第三方链接在前，测速IP在后
            add_content = custom_content + "\n".join(merged_nodes) + "\n"
            # ==========================================

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


async def _push_worker_proxy(final: list):
    cprint("\n正在推送到 Worker (config.json)...")
    try:
        async with aiohttp.ClientSession(
            headers={"User-Agent": cf_config.USER_AGENT},
            timeout=aiohttp.ClientTimeout(total=15)
        ) as session:

            # ── 登录 (修复：使用字典传参)
            r = await session.post(
                f"{cf_config.WORKER_HOST.rstrip('/')}/login",
                data={"password": cf_config.WORKER_PASSWORD}
            )

            # 修复：严格判断登录成功标志
            try:
                login_res = await r.json()
                if not login_res.get("success"):
                    cprint("   登录失败: 密码错误或 Worker 拒绝访问", level="warning")
                    return
            except Exception:
                cprint("   登录失败: 未获取到预期响应 (检查密码是否正确，或检查 WORKER_HOST 是否为 HTTPS)", level="warning")
                return

            # ── 构建候选 PROXYIP 列表
            cands_set: set[str] = set()
            cands = []
            for cc in cf_config.PROXYIP_PREFER_COUNTRIES:
                for n in final:
                    key = f"{n[0]}:{n[1]}"
                    if n[2] == cc and key not in cands_set:
                        cands_set.add(key)
                        cands.append(key)
            for n in final:
                key = f"{n[0]}:{n[1]}"
                if key not in cands_set:
                    cands_set.add(key)
                    cands.append(key)
            cands = cands[:cf_config.PROXYIP_COUNT]

            # ── 读取现有 config.json (修复：禁止跟随重定向，以防 Cookie 失效引发死循环)
            try:
                r_get = await session.get(
                    f"{cf_config.WORKER_HOST.rstrip('/')}/admin/config.json",
                    allow_redirects=False
                )
                if r_get.status != 200:
                    cprint(f"   读取 config.json 失败: HTTP {r_get.status} (Cookie已失效或配置为空)，跳过推送", level="warning")
                    return
                cfg = await r_get.json(content_type=None)
                if not isinstance(cfg, dict):
                    cprint("   config.json 格式异常（非对象），跳过推送", level="warning")
                    return
                if not cfg.get("UUID") or not cfg.get("HOST"):
                    cprint("   config.json 缺少 UUID 或 HOST 字段，跳过推送（避免覆盖为损坏配置）", level="warning")
                    return
            except Exception as e:
                cprint(f"   读取 config.json 异常: {type(e).__name__}: {e}，跳过推送", level="warning")
                return

            # ── 写入 PROXYIP 并推送
            cfg.setdefault("反代", {})["PROXYIP"] = ",".join(cands)
            payload = json.dumps(cfg, ensure_ascii=False).encode()

            r_put = await session.post(
                f"{cf_config.WORKER_HOST.rstrip('/')}/admin/config.json",
                data=payload,
                headers={"Content-Type": "application/json;charset=utf-8"},
            )
            if r_put.status != 200:
                body = await r_put.text()
                cprint(f"   推送失败: HTTP {r_put.status} - {body[:200]}", level="warning")
                return

            # ── 回读验证 (修复：添加 KV 最终一致性相关的延迟容错提示)
            try:
                r_verify = await session.get(
                    f"{cf_config.WORKER_HOST.rstrip('/')}/admin/config.json",
                    allow_redirects=False
                )
                if r_verify.status == 200:
                    cfg_verify = await r_verify.json(content_type=None)
                    actual = cfg_verify.get("反代", {}).get("PROXYIP", "")
                    expected = ",".join(cands)
                    if actual == expected:
                        cprint(f"   推送并验证成功: {expected}")
                    else:
                        cprint(
                            f"   推送操作已返回成功，但立即回读结果旧数据\n"
                            f"   (这是 Cloudflare KV 的正常现象，大约 60 秒后会在全球节点生效)\n"
                            f"   期望值: {expected}",
                            level="info"
                        )
                else:
                    cprint(f"   推送已成功，但回读验证请求失败: HTTP {r_verify.status}", level="warning")
            except Exception as e:
                cprint(f"   推送已成功，但回读验证阶段出现异常: {type(e).__name__}: {e}", level="warning")

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


def parse_args():
    parser = argparse.ArgumentParser(description="CF Optimizer")
    parser.add_argument("--mode", type=int, choices=[1, 2, 3], help="运行模式: 1=入口 2=代理 3=全部（覆盖 config）")
    parser.add_argument("--no-notify", action="store_true", help="禁用通知")
    parser.add_argument("--json-only", action="store_true", help="只输出 JSON，不推送 Worker")
    parser.add_argument("--top-n", type=int, help="覆盖 BW_TOP_N")
    return parser.parse_args()


args = parse_args()
if args.mode:
    cf_config.RUN_MODE = args.mode
if args.top_n:
    cf_config.BW_TOP_N = args.top_n


async def main():
    cprint("=" * 54)
    cprint(f"CF Optimizer v{VERSION}")
    cprint("=" * 54)

    start_time = time.monotonic()
    net_name = await get_current_net_name()
    cprint(f"当前网络环境: {net_name}")

    memory_db = load_memory()
    pruned = prune_stale(memory_db)
    if pruned:
        cprint(f"已清理 {pruned} 条过期记录")

    # 🆕 v4.2: 记忆库优先候选（已统一通过评分 + 置信度排序，移除 VIP 加权）
    priority_ips = get_priority_candidates(memory_db, top_n=100)

    cidr_weights = get_cidr_weights(memory_db, cf_config.CF_CIDR_LIST)
    cprint(f"记忆库: {len(memory_db)} 条记录，{len(priority_ips)} 个优先候选")

    if cf_config.RUN_MODE in [1, 3]:
        entrance_tasks = await collect_all_ips(
            load_premium=False, cidr_weights=cidr_weights, priority_ips=priority_ips
        )
        if entrance_tasks:
            await run_entrance_pipeline(entrance_tasks, net_name, memory_db)
        else:
            cprint("没有用于入口测试的 IP", level="warning")

    if cf_config.RUN_MODE in [2, 3]:
        proxy_tasks = await collect_all_ips(
            load_premium=True, cidr_weights=cidr_weights, priority_ips=priority_ips
        )
        if proxy_tasks:
            await run_proxy_pipeline(proxy_tasks, memory_db)
        else:
            cprint("没有用于代理测试的 IP", level="warning")

    elapsed = time.monotonic() - start_time
    cprint(f"\n任务完成，耗时 {elapsed:.0f} 秒")
    cprint(f"日志文件: {LOG_FILE}\n")

    summary = f"✅ CF Optimizer 完成\n网络: {net_name}\n耗时: {elapsed:.0f}s"
    await _notify(summary)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        cprint("\n已手动中断", level="warning")
        logger.warning("被用户中断")
