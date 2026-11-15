"""
CF优选助手 - 智能记忆模块 v4.4
v4.2 改动：删除 VIP 地区加权（target_ccs 参数）

优化内容：
  1. save_memory：heapq 替代全排序 + 原子写入（tempfile → os.replace），防崩溃数据丢失
  2. get_cidr_weights：bisect 二分查找替代双重遍历，O(N×M) → O(N log M)
  3. get_priority_candidates：heapq.nlargest 替代全排序
  4. 删除死代码 base_weight = 100.0
  5. v4.2：移除 target_ccs VIP 地区 ×1000 加权逻辑
"""
import bisect
import heapq
import ipaddress
import json
import os
import tempfile
import time

# 自动创建 Data 目录并存放记忆库
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Data")
os.makedirs(DATA_DIR, exist_ok=True)
MEMORY_FILE = os.path.join(DATA_DIR, "cf_memory.json")

STALE_DAYS      = 14    # 超过此天数未见且无历史成功 → 清除
DECAY_DAYS      = 7     # 超过此天数未见 → avg_score 开始衰减
MAX_FAIL_STREAK = 3     # 连续失败超过此次数 → 移出优先候选
MEMORY_MAX_SIZE = 5000  # 记忆库最多保留条目数（按置信度淘汰）
HOUR_BUCKETS    = 4     # 将24小时分成几段（4 = 每6小时一段）
MEMORY_FUSE_MIN_RUNS      = 2     # get_node_confidence 使用（同名参数，勿删）


def _hour_bucket() -> int:
    """当前时间属于哪个时间段（0~HOUR_BUCKETS-1）"""
    return time.localtime().tm_hour // (24 // HOUR_BUCKETS)


def load_memory() -> dict:
    if not os.path.exists(MEMORY_FILE):
        return {}
    try:
        with open(MEMORY_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_memory(db: dict):
    """保存记忆库。
    - 超出上限时用 heapq.nlargest 淘汰低分条目（O(N log K) 优于全排序 O(N log N)）
    - 原子写入：先写临时文件再 os.replace，防止写入中断导致 JSON 损坏
    """
    if len(db) > MEMORY_MAX_SIZE:
        now = time.time()

        def _confidence(item):
            _, rec = item
            days_ago = (now - rec.get("last_seen", 0)) / 86400
            freshness = max(0.0, 1.0 - days_ago / STALE_DAYS)
            passes = rec.get("passes", 0)
            return rec.get("avg_score", 0.0) * freshness * (passes > 0)

        top_items = heapq.nlargest(MEMORY_MAX_SIZE, db.items(), key=_confidence)
        keep_keys = {k for k, _ in top_items}
        for k in list(db.keys()):
            if k not in keep_keys:
                del db[k]

    # 原子写入：写临时文件 → rename，任何阶段崩溃都不会损坏原文件
    dir_name = os.path.dirname(MEMORY_FILE)
    with tempfile.NamedTemporaryFile(
        "w", dir=dir_name, delete=False, suffix=".tmp", encoding="utf-8"
    ) as tmp:
        json.dump(db, tmp, ensure_ascii=False, indent=2)
        tmp_path = tmp.name
    os.replace(tmp_path, MEMORY_FILE)


def record_result(db: dict, ip: str, port: int, cc: str,
                  passed: bool, score: float = 0.0,
                  ttfb_ms: float = 0.0, mbps: float = 0.0,
                  range_ok: bool = False,
                  stage: str = "full"):
    """记录扫描结果"""
    key = f"{ip}:{port}"
    now = time.time()
    bucket = _hour_bucket()

    rec = db.get(key, {
        "cc": cc, "first_seen": now, "runs": 0, "passes": 0, "fail_streak": 0,
        "last_seen": 0, "last_score": 0.0, "last_ttfb_ms": 0.0, "last_mbps": 0.0,
        "last_range_ok": False, "avg_score": 0.0, "stage_scores": {}, "tcp_hits": 0,
    })

    if cc:
        rec["cc"] = cc
    rec["last_seen"] = now

    if stage in ("full", "ttfb") and passed:
        rec["runs"] += 1
        rec["passes"] += 1
        rec["fail_streak"] = 0
        rec["last_score"] = score
        rec["last_ttfb_ms"] = ttfb_ms
        rec["last_mbps"] = mbps
        rec["last_range_ok"] = range_ok
        rec["avg_score"] = rec["avg_score"] * 0.6 + score * 0.4
        bucket_key = str(bucket)
        bucket_scores = rec["stage_scores"].get(bucket_key, [])
        bucket_scores.append(score)
        rec["stage_scores"][bucket_key] = bucket_scores[-10:]
    elif stage == "tcp":
        rec["tcp_hits"] = rec.get("tcp_hits", 0) + 1
        rec["fail_streak"] = 0
    elif stage == "trace":
        rec["tcp_hits"] = rec.get("tcp_hits", 0) + 1
        rec["fail_streak"] = 0
    elif stage == "fail":
        rec["runs"] += 1
        rec["fail_streak"] = rec.get("fail_streak", 0) + 1

    db[key] = rec


def get_priority_candidates(db: dict, top_n: int = 100) -> list:
    """返回优先候选，按综合置信度排序。
    使用 heapq.nlargest 替代全排序，只需维护 top_n 大小的堆。

    v4.2 改动：移除 target_ccs 参数（VIP 加权逻辑已废弃）
    """
    now = time.time()
    current_bucket = str(_hour_bucket())
    candidates = []

    for key, rec in db.items():
        days_ago = (now - rec.get("last_seen", 0)) / 86400
        fail_streak = rec.get("fail_streak", 0)
        passes = rec.get("passes", 0)

        if days_ago > STALE_DAYS or fail_streak >= MAX_FAIL_STREAK:
            continue
        if passes == 0 and rec.get("tcp_hits", 0) < 3:
            continue

        pass_rate = passes / max(rec.get("runs", 1), 1)
        freshness = max(0.0, 1.0 - days_ago / STALE_DAYS)
        decay_factor = (
            max(0.3, 1.0 - (days_ago - DECAY_DAYS) / (STALE_DAYS - DECAY_DAYS))
            if days_ago > DECAY_DAYS else 1.0
        )

        avg = rec.get("avg_score", 0.0) * decay_factor
        confidence = avg * pass_rate * freshness

        bucket_scores = rec.get("stage_scores", {}).get(current_bucket, [])
        if bucket_scores:
            time_bonus = (sum(bucket_scores) / len(bucket_scores)) / 100.0 * 0.2
            confidence *= (1.0 + time_bonus)

        try:
            ip, port = key.rsplit(":", 1)
            candidates.append((confidence, ip, int(port), rec.get("cc", "")))
        except ValueError:
            continue

    top = heapq.nlargest(top_n, candidates, key=lambda x: x[0])
    return [(ip, port, cc) for _, ip, port, cc in top]


def get_cidr_weights(db: dict, cidr_list: list) -> list:
    """CIDR 权重计算。
    用 bisect 二分查找替代双重遍历，复杂度从 O(N×M) 降为 O(N log M)。
    适用于 CIDR 网段无大量嵌套重叠的场景（CF 网段符合此条件）。
    """
    current_bucket = str(_hour_bucket())
    cidr_stats = {cidr: {"passes": 0, "total": 0, "time_passes": 0} for cidr in cidr_list}

    # 预解析：转为整数边界 (start, end, cidr, num_addrs)
    parsed_nets = []
    for cidr in cidr_list:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            parsed_nets.append((
                int(net.network_address),
                int(net.broadcast_address),
                cidr,
                net.num_addresses,
            ))
        except ValueError:
            parsed_nets.append((-1, -1, cidr, 1))

    # 仅对合法网段建立有序索引，用于 bisect
    valid_nets = sorted(
        [n for n in parsed_nets if n[0] != -1],
        key=lambda x: x[0]
    )
    starts = [n[0] for n in valid_nets]  # bisect 的查找列表

    # O(N log M)：每个 IP 用 bisect 定位候选网段，不再全量遍历
    for key, rec in db.items():
        try:
            ip_str = key.rsplit(":", 1)[0]
            ip_int = int(ipaddress.ip_address(ip_str))
        except ValueError:
            continue

        # 找最后一个 start <= ip_int 的位置，由于 CF 网段不重叠，只需检查该网段即可
        idx = bisect.bisect_right(starts, ip_int) - 1
        if idx >= 0:
            start, end, cidr, _ = valid_nets[idx]
            if ip_int <= end:
                cidr_stats[cidr]["total"] += 1
                if rec.get("passes", 0) > 0:
                    cidr_stats[cidr]["passes"] += 1
                if rec.get("stage_scores", {}).get(current_bucket):
                    cidr_stats[cidr]["time_passes"] += 1

    # 结算权重（已删除无效的 base_weight = 100.0 死代码）
    weights = []
    for start, end, cidr, num_addrs in parsed_nets:
        if start == -1:
            weights.append(1.0)
            continue
        base_weight = float(num_addrs)
        stats = cidr_stats[cidr]
        if stats["total"] > 5:
            pass_rate = stats["passes"] / stats["total"]
            time_bonus = min(0.3, stats["time_passes"] / max(stats["total"], 1) * 0.5)
            modifier = 0.2 + 0.8 * pass_rate + time_bonus
            weights.append(base_weight * modifier)
        else:
            weights.append(base_weight)

    return weights


def get_node_confidence(db: dict, ip: str, port: int) -> float:
    """取单节点记忆库置信度（0~100），用于最终推送融合排序。
    - 无记录 / passes 不足 → 返回 None（调用方按纯本轮分处理）
    - 置信度 = avg_score × 衰减系数 × (passes>=MIN_RUNS ? 1 : None)
    """
    rec = db.get(f"{ip}:{port}")
    if not rec:
        return None
    passes = rec.get("passes", 0)
    if passes < MEMORY_FUSE_MIN_RUNS:
        return None
    now = time.time()
    days_ago = (now - rec.get("last_seen", 0)) / 86400
    freshness = max(0.0, 1.0 - days_ago / STALE_DAYS)
    if freshness <= 0:
        return None
    return rec.get("avg_score", 0.0) * freshness


def prune_stale(db: dict) -> int:
    """清除过期/低质量条目"""
    now = time.time()
    to_delete = []
    for key, rec in db.items():
        days_ago = (now - rec.get("last_seen", 0)) / 86400
        passes = rec.get("passes", 0)
        fail_streak = rec.get("fail_streak", 0)
        tcp_only = passes == 0 and rec.get("tcp_hits", 0) > 0

        if days_ago > STALE_DAYS and passes == 0:
            to_delete.append(key)
        elif fail_streak >= MAX_FAIL_STREAK * 2 and days_ago > 7:
            to_delete.append(key)
        elif tcp_only and days_ago > STALE_DAYS / 2:
            to_delete.append(key)

    for key in to_delete:
        del db[key]
    return len(to_delete)
