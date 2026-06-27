# 安装指南

## 前提条件
- Python 3.8+
- 确保已安装 `pip`

## 快速开始

1. **克隆项目**:
   ```bash
   git clone <你的仓库地址>
   cd CF-Optimizer
   ```

2. **安装依赖**:
   ```bash
   pip install -r requirements.txt
   ```

3. **配置**:
   修改 `cf_config.py` 中的 `WORKER_HOST` 和 `WORKER_PASSWORD`，配置你的 Cloudflare Worker 服务端信息。

4. **运行**:
   ```bash
   # 运行全部模式（入口+代理）
   python cf_optimizer.py --mode 3
   ```
