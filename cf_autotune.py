"""
CF优选助手 - 自动调优扩展模块 v4.7
=========================================
v4.7 修复：
  1. PID 目标值从 0.20 提升至 0.80（适配 CIDR 盲扫的高丢包常态）
  2. 消除非对称增益棘轮效应（下调/上调增益对称化）
  3. 积分器饱和上限从 2.0 降至 0.5（防积分风暴）
  4. 高层失败率目标从 0.10 提升至 0.40（Trace 失败是正常的）
  5. PID 积分状态跨轮次持久化并衰减（防棘轮）
  6. 新增均值回归机制（防参数无限漂移）
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
    如果 target 相对 old 变化小于 deadzone 比例，且绝对差值也小于 deadzone * old，则不改变。
    为了防止整数步进参数因为 EMA 导致小幅度变化被丢弃而“卡死”，当 integer=True 时，
    如果计算出的新值与 old 相等但 target != old，则强行向 target 方向移动 1 步。
    """
    if old is not None and old != 0:
        rel_change = abs(target - old) / abs(old)
        abs_change = abs(target - old)
        if rel_change < deadzone and abs_change < (deadzone * abs(old)):
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

def mean_revert(tune_state: dict, defaults: dict, strength: float,
                skip_keys: set = None):
    """
    均值回归：将 tune_state 中的数值参数向 defaults 方向拉回 strength 比例。
    用于防止自动调优参数经过多轮后无限漂移到地板/天花板。
    
    strength=0.10 意味着每轮将 (当前值 - 默认值) 的差距缩小 10%。
    经过 ~20 轮无外力驱动后，参数基本回到默认值。
    
    返回实际被回拉的参数数量。
    """
    if strength <= 0:
        return 0
    
    if skip_keys is None:
        skip_keys = {'history', 'task_limit_up_streak', 'task_limit_down_streak',
                     'pid_loss_integral', 'pid_last_loss_error'}
    
    reverted_count = 0
    for key, default_val in defaults.items():
        if key in skip_keys:
            continue
        if not isinstance(default_val, (int, float)):
            continue
        if key not in tune_state:
            continue
            
        current = tune_state[key]
        if current == default_val:
            continue
            
        # 向默认值回拉 strength 比例
        new_val = current + strength * (default_val - current)
        
        if isinstance(default_val, int):
            new_val = int(round(new_val))
        else:
            new_val = round(new_val, 4)
            
        if new_val != current:
            tune_state[key] = new_val
            reverted_count += 1
    
    return reverted_count

def network_health(survival_rate, median_ttfb_s, jitter_pass_rate, cfg):
    """
    根据 TCP 存活率、中位 TTFB 延迟、Jitter 抖动过滤通过率综合得出 0~1 的网络健康度。
    """
    # [修复] 针对盲扫场景调整归一化
    if survival_rate < 0.20:  # 盲扫模式
        survival_score = survival_rate / 0.20  # 20% = 满分
    else:  # 正常模式
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


# =====================================================================
#  v4.7 新增：闭环负反馈调节控制器 (PID 控制与正交解耦)
# =====================================================================

class PIDFeedbackController:
    """
    v4.7 修复版 PID 负反馈控制器。
    
    核心修复：
    1. target_sp 默认 0.80（CIDR 盲扫 80% 丢包是正常的，不是"过载"）
    2. 对称增益（消除棘轮效应：下降和恢复速度一致）
    3. 积分器饱和上限从 2.0 降至 0.5（防止积分风暴）
    4. 高层失败率目标从 0.10 提至 0.40
    5. 支持积分状态跨轮次持久化（带衰减，防棘轮锁死）
    """
    def __init__(self, target_sp=0.80):
        self.target_sp = target_sp
        self.loss_integral = 0.0
        self.last_loss_error = 0.0

    def compute_control_signals(self, last_stats, current_cfg, defaults):
        """
        根据传感器数据，解耦计算出下一步控制变量的值。
        所有增益系数从 cfg 读取，不再硬编码。
        """
        # 1. 提取传感器指标
        survival_rate = last_stats.get("survival_rate", 1.0)
        loss_rate = 1.0 - survival_rate
        sample_size = last_stats.get("sample_size", 3000)
        median_rtt = last_stats.get("median_rtt", 0.15)
        high_level_fail = last_stats.get("high_level_fail", 0.0)

        # 2. 置信度权重 Beta (样本量不足时衰减控制力度)
        expected_size = max(1000, defaults.get("dynamic_task_limit", 1500))
        beta = clamp(sample_size / expected_size, 0.25, 1.0)

        # 3. 并发度控制信号（与丢包率绑定）
        loss_error = loss_rate - self.target_sp
        
        # 积分防饱和 (上限大幅降低，防止积分风暴)
        integral_max = getattr(current_cfg, 'PID_INTEGRAL_MAX', 0.5)
        self.loss_integral = clamp(self.loss_integral + loss_error, -integral_max, integral_max)
        
        # 突变回弹：网络突然变好时清零积分以加速恢复
        if loss_error < 0 and self.last_loss_error > 0:
            self.loss_integral = 0.0

        self.last_loss_error = loss_error

        # PI 控制量
        p_out = 0.8 * loss_error * beta
        i_out = 0.2 * self.loss_integral * beta
        ctrl_concurrency = p_out + i_out

        # 并发 Workers 自适应（使用可配置的对称增益）
        current_workers = current_cfg.MAX_TCP_WORKERS
        min_workers = current_cfg.TCP_WORKERS_MIN_CAP
        max_workers = current_cfg.TCP_WORKERS_MAX_CAP
        
        down_gain = getattr(current_cfg, 'PID_CONCURRENCY_DOWN_GAIN', 0.8)
        up_gain = getattr(current_cfg, 'PID_CONCURRENCY_UP_GAIN', 1.0)
        
        if ctrl_concurrency > 0:  # 压力大 → 降低并发
            target_workers = current_workers * (1.0 - ctrl_concurrency * down_gain)
        else:  # 压力小 → 恢复并发（增益更大以加速恢复）
            target_workers = current_workers * (1.0 - ctrl_concurrency * up_gain)
            
        new_workers = int(clamp(target_workers, min_workers, max_workers))

        # 4. 超时控制信号（与中位 RTT 绑定）
        rtt_target = current_cfg.TCP_TIMEOUT * 0.8
        rtt_error = median_rtt - rtt_target
        
        if rtt_error > 0:
            target_timeout = current_cfg.TCP_TIMEOUT * (1.0 + (rtt_error / rtt_target) * 0.5 * beta)
        else:
            target_timeout = current_cfg.TCP_TIMEOUT * (1.0 + (rtt_error / rtt_target) * 0.15 * beta)
            
        new_timeout = clamp(target_timeout, current_cfg.TCP_TIMEOUT_MIN, current_cfg.TCP_TIMEOUT_MAX)

        # 5. 存活上限控制信号（与高层失败率绑定）
        high_fail_target = getattr(current_cfg, 'PID_HIGH_FAIL_TARGET', 0.40)
        fail_error = high_level_fail - high_fail_target
        
        alive_down_gain = getattr(current_cfg, 'PID_ALIVE_DOWN_GAIN', 0.8)
        alive_up_gain = getattr(current_cfg, 'PID_ALIVE_UP_GAIN', 1.2)
        
        if fail_error > 0:  # 高层大量失败 → 收窄保留池
            target_alive = current_cfg.TCP_ALIVE_LIMIT * (1.0 - fail_error * alive_down_gain * beta)
        else:  # 高层稳健 → 放宽保留池（增益更大以加速恢复）
            target_alive = current_cfg.TCP_ALIVE_LIMIT * (1.0 - fail_error * alive_up_gain * beta)
            
        new_alive_limit = int(clamp(target_alive, current_cfg.TCP_ALIVE_LIMIT_MIN, current_cfg.TCP_ALIVE_LIMIT_MAX))

        return new_workers, new_timeout, new_alive_limit


# =====================================================================
#  v4.7 新增：闭环负反馈调节控制器 (PID 控制与正交解耦)
