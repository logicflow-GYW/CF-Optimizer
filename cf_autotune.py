"""
CF优选助手 - 自动调优扩展模块 v4.6
=========================================
提供平滑算法、死区过滤、边界限制、健康度指标计算及状态管理。
"""
import os
import json
import tempfile

def clamp(v, lo, hi):
    return max(lo, min(hi, v))

def percentile(sorted_list, p):
    """
    计算已排序列表 sorted_list 的 p 分位数 (p在0..1之间)
    """
    if not sorted_list:
        return 0.0
    idx = max(0, min(len(sorted_list) - 1, int(len(sorted_list) * p)))
    return sorted_list[idx]

def smooth_update(old, target, *, alpha, deadzone, lo, hi, integer=False):
    """
    EMA + 死区 + 边界限制。
    如果 target 相对 old 变化小于 deadzone 比例，则不改变。
    为了防止整数步进参数因为 EMA 导致小幅度变化被丢弃而“卡死”，当 integer=True 时，
    如果计算出的新值与 old 相等但 target != old，则强行向 target 方向移动 1 步。
    """
    if old is not None and old != 0:
        if abs(target - old) / abs(old) < deadzone:
            return old, False
    
    val = old * (1.0 - alpha) + target * alpha
    val = clamp(val, lo, hi)
    
    if integer:
        val = int(round(val))
        if val == old and target != old:
            # 强行向目标方向移动 1 步
            val = clamp(old + (1 if target > old else -1), lo, hi)
            
    # 返回 (新值, 是否变化)
    return val, (val != old)

def network_health(survival_rate, median_ttfb_s, jitter_pass_rate, cfg):
    """
    根据 TCP 存活率、中位 TTFB 延迟、Jitter 抖动过滤通过率综合得出 0~1 的网络健康度。
    """
    # 存活率在 25% 以上计满分 1.0
    survival_score = min(survival_rate / 0.25, 1.0)
    
    # 延迟在 0.8s 以下，随着越接近 0 分数越高；大于等于 0.8s 计 0 分
    ttfb_val = median_ttfb_s if median_ttfb_s is not None else 0.8
    latency_score = max(0.0, 1.0 - ttfb_val / 0.8)
    
    # jitter 过关率直接作为分数
    jitter_score = jitter_pass_rate if jitter_pass_rate is not None else 0.0
    
    health = (
        cfg.HEALTH_W_SURVIVAL * survival_score +
        cfg.HEALTH_W_LATENCY * latency_score +
        cfg.HEALTH_W_JITTER * jitter_score
    )
    return clamp(health, 0.0, 1.0)

def load_state(path, defaults):
    if not os.path.exists(path):
        return defaults.copy()
    try:
        with open(path, "r", encoding="utf-8") as f:
            state = json.load(f)
            # 确保 defaults 中的键都在 state 中
            for k, v in defaults.items():
                if k not in state:
                    state[k] = v
            return state
    except Exception:
        return defaults.copy()

def write_state(path, state):
    dir_name = os.path.dirname(path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
    try:
        with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, suffix=".tmp", encoding="utf-8") as tmp:
            json.dump(state, tmp, ensure_ascii=False, indent=2)
            tmp_path = tmp.name
        os.replace(tmp_path, path)
    except Exception:
        pass

def record_history(state, entry, max_len):
    if "history" not in state:
        state["history"] = []
    state["history"].append(entry)
    if len(state["history"]) > max_len:
        state["history"] = state["history"][-max_len:]

def reset_state(path):
    if os.path.exists(path):
        try:
            os.remove(path)
            print("   -> 已成功重置动态调优状态文件")
        except Exception as e:
            print(f"   -> 无法删除状态文件: {e}")
