# 配置说明

在 `cf_config.py` 中，你可以调整以下关键参数：

### 核心参数
- `RUN_MODE`: 运行模式 (1=入口, 2=代理, 3=全部)
- `MAX_TCP_WORKERS`: TCP 连接探测并发（根据网速调整）
- `TTFB_MAX`: TTFB 延迟上限（秒）
- `BW_MB`: 下载测速数据量（MB）

### 智能推送
- `SMART_PUSH_MIN_SCORE`: 智能推送的最低评分阈值
- `SMART_PUSH_IPS_PER_CC`: 每个地区推送的最优节点数

详情请参考 `cf_config.py` 中的代码注释。
