# 🚀 CF Optimizer (Cloudflare 优选助手)

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**CF Optimizer** 是一款极高性能的 Cloudflare 入口 IP 及代理 IP 优选工具。它不再是简单的“暴力扫描”，而是引入了**智能记忆机制**和**环境自适应调优**，旨在为不同网络环境下寻找最优的 Cloudflare 接入点。

## ✨ 核心特性

- **🧠 智能记忆库 (`cf_memory`)**: 
  - 记录节点的历史表现，通过**置信度算法**（评分 × 新鲜度 × 通过率）决定优先级。
  - **CIDR 权重分析**: 根据历史成功率，动态调整盲扫网段的权重，提高命中率。
  - **时段分析**: 记录 24 小时分段评分，自动在不同时段推荐最稳节点。
- **⚙️ 环境自适应 (Auto-Tuning)**: 
  - **防拥塞保护**: 实时监测 TCP 存活率，自动降低并发数以防止路由器丢包。
  - **动态阈值**: 根据当前网络质量，自动收紧或放宽 TTFB 延迟门槛。
  - **带宽量力而行**: 根据极限带宽自动调整测速包大小和并发数，避免挤兑。
- **🌐 全自动源获取**: 
  - 内置“动态通讯录”模式，自动抓取最新订阅源及 CIDR 网段。
- **🛠️ 完整生态闭环**: 
  - **多网合并**: 支持多网络环境运行，自动标记“多网通吃”节点。
  - **Worker 集成**: 一键将优选结果推送到 Cloudflare Worker (ADD.txt/config.json)。
  - **可视化看板**: 提供 `view_memory.html` 本地查看测速数据。

## 📖 文档
- [安装指南](INSTALL.md)
- [配置参数说明](CONFIG.md)
