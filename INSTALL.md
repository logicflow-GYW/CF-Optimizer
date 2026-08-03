# 安装指南

## 前提条件
- Python 3.8+
- 网络可访问 Cloudflare 相关域名（测速需要）

## 快速开始

1. **克隆项目**:
   ```bash
   git clone https://github.com/logicflow-GYW/CF-Optimizer.git
   cd CF-Optimizer
   ```

2. **安装依赖**（仅需 `aiohttp`；主程序检测缺失时也会自动尝试安装）:
   ```bash
   pip install -r requirements.txt
   ```

3. **配置**:
   编辑 `cf_config.py`，或用环境变量注入（推荐，避免密码写入代码）:
   ```bash
   export CF_WORKER_HOST="https://your-worker.example.com"   # edgetunnel 域名
   export CF_WORKER_PASSWORD="你的edgetunnel后台密码"          # 对应 edgetunnel 的 ADMIN 变量
   ```

4. **运行**:
   ```bash
   python cf_optimizer.py
   ```

   常用参数:
   ```bash
   python cf_optimizer.py --top-n 6          # 调整输出节点数
   python cf_optimizer.py --json-only        # 只输出结果，不推送 Worker
   python cf_optimizer.py --no-autotune      # 本轮禁用动态调优
   python cf_optimizer.py --reset-autotune   # 重置调优状态
   ```

## 与 edgetunnel 搭配

1. 部署 [edgetunnel](https://github.com/cmliu/edgetunnel) 到 Cloudflare Workers / Pages，设置环境变量 `ADMIN` 为后台密码。
2. 本项目 `WORKER_HOST` 填 edgetunnel 域名，`WORKER_PASSWORD` 与 `ADMIN` 一致。
3. 运行后自动推送优选结果到 `{WORKER_HOST}/admin/ADD.txt`，edgetunnel 订阅地址即时生效。

## 输出
- `Output/entry_ip_<网络>.txt`：本次优选结果
- `Output/ADD_merged.txt`：多网合并文件
- `Data/autotune_state.json`：动态调优状态
- `Logs/`：运行日志
- `view_memory.html`：浏览器打开可查看记忆库与测速数据