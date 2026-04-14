# Trace-Eye Demo 运行模式说明

## 概述

Trace-Eye Demo 支持两种运行模式：

- **DEBUG 模式** (默认): 使用真实的算法和逻辑处理数据
- **DEMO 模式**: 直接返回预先生成的 JSON 文件，用于快速演示

## 模式切换

### 方式一：环境变量 (推荐)

```bash
# Debug 模式 (真实处理)
set TRACE_EYE_MODE=debug
python app.py

# Demo 模式 (快速演示)
set TRACE_EYE_MODE=demo
python app.py
```

Linux/Mac:
```bash
export TRACE_EYE_MODE=demo
python app.py
```

### 方式二：修改代码

在 `app.py` 文件开头找到：

```python
MODE = os.environ.get("TRACE_EYE_MODE", "debug").lower()
```

修改 `"debug"` 为 `"demo"` 即可切换到 Demo 模式。

## 模式差异

### Debug 模式 (debug)

- **数据生成**: 使用 `DataGenerator` 和 `LogGenerator` 生成真实的多格式日志
- **日志解析**: 使用 `LogParser` 解析 syslog、文件审计、NetFlow 格式日志
- **事件提取**: 使用 `EventExtractor` 提取统一格式事件
- **图构建**: 使用 `GraphBuilder` 构建关系图并去噪
- **规则检测**: 使用 `RuleEngine` 进行 25 条规则匹配
- **威胁检测**: 使用 `ThreatDetector` (Isolation Forest + K-Means) 进行威胁评分
- **关系挖掘**: 使用 `RelationMiner` 挖掘可疑关系
- **攻击链重建**: 使用 `AttackChainBuilder` 重建攻击链

**适用场景**:
- 算法验证和调试
- 理解系统工作原理
- 学术研究和技术演示

### Demo 模式 (demo)

- **数据加载**: 直接从 `data/demo/` 目录加载预生成的 JSON 文件
- **步骤执行**: 所有步骤接口立即返回成功，使用模拟数据
- **数据展示**: 前端可以完整查看所有分析结果

**适用场景**:
- 快速功能演示
- UI/UX 测试
- 客户展示
- 不需要等待处理时间的场景

## 数据文件结构

### Debug 模式

```
data/
├── data_logs.json          # 原始日志
├── data_events.json        # 事件提取结果
├── data_graph.json         # 关系图数据
├── data_alerts.json        # 规则检测告警
├── data_threat.json        # 威胁检测结果
├── data_relations.json     # 关系挖掘结果
├── data_chains.json        # 攻击链重建结果
├── data_analysis.json      # 最终分析报告
├── syslog.log              # 进程日志
├── file_audit.log          # 文件日志
└── netflow.log            # 网络日志
```

### Demo 模式

```
data/
└── demo/                   # Demo 专用数据目录
    ├── data_events.json
    ├── data_graph.json
    ├── data_alerts.json
    ├── data_threat.json
    ├── data_relations.json
    ├── data_chains.json
    └── data_analysis.json
```

## API 响应差异

### /api/status 接口

Debug 模式响应:
```json
{
  "status": "idle",
  "mode": "DEBUG",
  "steps_status": {
    "upload": {"completed": true, "has_data": true},
    ...
  }
}
```

Demo 模式响应:
```json
{
  "status": "idle",
  "mode": "DEMO",
  "demo_mode": true,
  "demo_message": "当前为演示模式，数据已预加载",
  "steps_status": {
    "upload": {"completed": true, "has_data": true},
    "extract": {"completed": true, "has_data": true},
    ...
  }
}
```

## 步骤接口响应

Demo 模式下，所有步骤接口 (`/api/step/*`) 立即返回成功，包含预定义的统计数据：

```json
{
  "success": true,
  "message": "事件提取完成 (演示模式)",
  "statistics": { ... }
}
```

## 启动示例

### Windows (PowerShell)

```powershell
# Debug 模式
$env:TRACE_EYE_MODE="debug"
python app.py

# Demo 模式
$env:TRACE_EYE_MODE="demo"
python app.py
```

### Windows (CMD)

```cmd
REM Debug 模式
set TRACE_EYE_MODE=debug
python app.py

REM Demo 模式
set TRACE_EYE_MODE=demo
python app.py
```

### Linux/Mac

```bash
# Debug 模式
TRACE_EYE_MODE=debug python app.py

# Demo 模式
TRACE_EYE_MODE=demo python app.py
```

## 验证当前模式

启动应用后，在控制台可以看到：

```
╔══════════════════════════════════════════════════════════════╗
║          Trace-Eye Demo - APT 威胁检测系统                  ║
║                                                            ║
║  当前模式: DEBUG (调试模式 - 真实处理)                    ║
║  使用真实算法处理数据                                     ║
║                                                            ║
║  环境变量: TRACE_EYE_MODE=debug                            ║
║  访问地址: http://localhost:5000                            ║
╚══════════════════════════════════════════════════════════════╝
```

或通过 API 查询:

```bash
curl http://localhost:5000/api/status
```

响应中的 `mode` 字段会显示当前模式。
