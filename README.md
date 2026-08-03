# 🚀 CF Optimizer (Cloudflare 优选助手)

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**CF Optimizer** 是一款极高性能的 **Cloudflare 入口 IP 优选工具**，专为搭配 [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) 这类 Cloudflare Worker / Pages 隧道代理设计。

它不再是简单的“暴力扫描”，而是引入了**智能记忆机制**和**环境自适应动态调优**，为不同网络环境寻找最优的 Cloudflare 接入点，并把优选结果**一键推送到你的 edgetunnel 后台**，让订阅地址里的节点自动切换到最优 IP。

## 🤝 与 edgetunnel 搭配使用

本项目的关键能力就是对接 edgetunnel 的**后台更新订阅**接口：

1. 在 Cloudflare Workers / Pages 部署 [edgetunnel](https://github.com/cmliu/edgetunnel)，并设置环境变量 `ADMIN` 为你的后台密码。
2. 在本项目的 `cf_config.py` 中配置：
   - `WORKER_HOST`：你的 edgetunnel 域名（如 `https://your-worker.example.com`）
   - `WORKER_PASSWORD`：与 edgetunnel 的 `ADMIN` 密码一致
3. 运行优选后，工具会自动：
   - `POST {WORKER_HOST}/login` 登录（密码校验）
   - `POST {WORKER_HOST}/admin/ADD.txt` 推送优选节点 → **edgetunnel 订阅地址自动更新为优选 IP**

> 也可以配合 `--json-only` 只输出结果到本地，不推送 Worker，由你自己决定如何接入。

## ✨ 核心特性

- **🧠 智能记忆库 (`cf_memory`)**:
  - 记录节点历史表现，通过**置信度算法**（评分 × 新鲜度 × 通过率）决定优先级。
  - **CIDR 权重分析**：根据历史成功率动态调整盲扫网段权重，提高命中率。
  - **时段分析**：记录 24 小时分段评分，自动在不同时段推荐最稳节点。
- **⚙️ 动态自动调优 (`cf_autotune`, v4.6 新增)**:
  - **EMA 平滑 + 死区防抖**：连接数、超时、TTFB 阈值等参数平滑变动，避免频繁抖动。
  - **健康度评分**：综合存活率、延迟、抖动自动收紧或放宽各项阈值。
  - **防拥塞保护**：TCP 存活率偏低时自动降低并发，防止路由器丢包。
  - **带宽量力而行**：根据极限带宽自动调整测速数据量，避免挤兑。
- **🌐 全自动源获取**: 内置“动态通讯录”模式，自动抓取最新订阅源及 CIDR 网段。
- **🔀 多网合并**: 支持多网络环境运行，自动标记“多网通吃”节点并合并输出。
- **📊 可视化看板**: 提供 `view_memory.html` 本地查看测速数据与记忆库。

## 🚀 快速开始

```bash
git clone https://github.com/logicflow-GYW/CF-Optimizer.git
cd CF-Optimizer
pip install -r requirements.txt    # 仅需要 aiohttp；主程序也会自动尝试安装

# 直接运行（默认入口优选模式）
python cf_optimizer.py
```

常用参数：

| 参数 | 说明 |
|------|------|
| `--no-notify` | 禁用通知 |
| `--json-only` | 只输出 JSON，不推送 Worker |
| `--top-n N` | 覆盖 `BW_TOP_N` 与 `SMART_PUSH_MAX_TOTAL` |
| `--reset-autotune` | 重置动态调优状态，回到配置默认值 |
| `--no-autotune` | 本轮禁用自动调节 |

## ⚙️ 配置

编辑 `cf_config.py` 调整各项参数（详见 [CONFIG.md](CONFIG.md)），其中与 edgetunnel 对接、以及通知相关的敏感值，**建议通过环境变量注入，避免写入代码**：

| 环境变量 | 用途 | 默认值 |
|----------|------|--------|
| `CF_WORKER_HOST` | edgetunnel Worker 地址 | `https://your-worker.example.com` |
| `CF_WORKER_PASSWORD` | edgetunnel 后台密码（对应 `ADMIN`） | 空（需自行设置） |
| `CF_WEBHOOK_URL` | 推送通知 Webhook | 空 |
| `CF_TG_TOKEN` | Telegram Bot Token | 空 |
| `CF_TG_CHAT_ID` | Telegram 聊天 ID | 空 |

示例：

```bash
export CF_WORKER_HOST="https://your-worker.example.com"
export CF_WORKER_PASSWORD="你的后台密码"
python cf_optimizer.py
```

## 📚 文档
- [安装指南](INSTALL.md)
- [配置参数说明](CONFIG.md)

## 📄 输出文件
- `Output/entry_ip_<网络>.txt` — 单网络优选结果
- `Output/ADD_merged.txt` — 多网合并后的推送文件
- `Output/Tested_Nodes/` — 历史测速明细
- `Data/autotune_state.json` — 动态调优状态（可用 `--reset-autotune` 重置）
- `Logs/cf_entrance_optimizer.log` — 运行日志

## 📝 License
[MIT](LICENSE)