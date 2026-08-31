# Trace-Eye Demo - 项目说明

## 项目概述

**Trace-Eye Demo** 是一个基于溯源图和机器学习的 APT（高级持续性威胁）检测演示系统。

### 核心功能

1. **多源日志处理**：支持进程日志(syslog)、文件审计日志、网络流量日志(NetFlow)、JSON格式日志
2. **事件提取**：将多源日志解析为统一事件格式
3. **关系图构建**：构建系统调用溯源图，自动去噪（过滤系统服务、移除高频边、删除孤立节点）
4. **规则检测**：基于 25 条预定义规则进行异常检测，覆盖文件、进程、网络、行为序列、时序异常 5 大类
5. **威胁检测**：使用 Isolation Forest（异常检测）和 K-Means（行为聚类）进行威胁评分
6. **关系挖掘**：挖掘异常节点周围的可疑关系和可疑子图
7. **攻击链重建**：使用 DBSCAN 聚类和 ATT&CK 框架映射重建攻击链
8. **AI 智能分析**：基于大模型的告警降噪与攻击故事生成（支持真实/模拟两种模式）

## 技术栈

- **后端**: Python 3.8+ + Flask
- **前端**: 原生 HTML/CSS/JavaScript
- **可视化**: ECharts 5.4.3
- **机器学习**: Isolation Forest、K-Means、DBSCAN
- **数据存储**: JSON 文件

## 项目结构

```
trace-eye-demo/
├── app.py                      # Flask 主应用入口
├── requirements.txt            # Python 依赖
├── modules/                    # 核心处理模块
│   ├── __init__.py
│   ├── data_generator.py       # 日志数据生成器
│   ├── event_extractor.py      # 事件提取器
│   ├── graph_builder.py        # 关系图构建器
│   ├── rule_engine.py          # 规则引擎（25条规则）
│   ├── relation_miner.py       # 关系挖掘器
│   ├── threat_detector.py      # 威胁检测器（ML算法）
│   ├── attack_chain_builder.py # 攻击链重建器
│   ├── llm_analyzer.py         # AI 分析模块
│   ├── log_generator.py        # 多格式日志生成器
│   ├── log_parser.py           # 日志解析器
│   └── cache_manager.py        # 缓存管理器
├── templates/
│   └── index.html              # 单页应用主页面
├── static/
│   ├── css/
│   │   └── style.css           # 样式文件（约1600行）
│   └── js/
│       └── main.js             # 前端逻辑（约1580行）
├── data/                       # 数据存储目录
│   ├── data_logs.json          # 原始日志
│   ├── data_events.json        # 事件提取结果
│   ├── data_graph.json         # 关系图数据
│   ├── data_alerts.json        # 规则检测告警
│   ├── data_threat.json        # 威胁检测结果
│   ├── data_relations.json     # 关系挖掘结果
│   ├── data_chains.json        # 攻击链重建结果
│   ├── data_analysis.json      # 最终分析报告
│   └── demo/                   # 演示模式预生成数据
│       ├── data_events.json
│       ├── data_graph.json
│       ├── data_alerts.json
│       ├── data_threat.json
│       ├── data_relations.json
│       ├── data_chains.json
│       └── data_analysis.json
├── .gitignore                  # Git 忽略配置
├── README.md                   # 项目文档
└── CLAUDE.md                   # 本文件
```

## 运行模式

系统支持两种运行模式，通过环境变量 `TRACE_EYE_MODE` 控制：

### DEBUG 模式（默认调试模式）

```bash
export TRACE_EYE_MODE=debug
python app.py
```

- 使用真实算法处理数据
- 支持上传日志文件或生成测试数据
- 每个步骤需要手动执行
- 适合开发和调试

### DEMO 模式（演示模式，默认）

```bash
export TRACE_EYE_MODE=demo
# 或不设置环境变量，默认为 demo
python app.py
```

- 使用预生成的 JSON 数据直接展示
- 所有步骤自动标记为已完成
- 无需等待处理，即时查看结果
- 适合演示和展示

## 处理流程

系统采用分步骤流水线处理：

1. **数据准备** (`/api/upload` 或 `/api/generate`)
   - 上传日志文件：支持多文件上传，自动检测日志类型
   - 生成测试数据：生成包含攻击场景的模拟日志

2. **事件提取** (`/api/step/extract`)
   - 解析多源日志为统一事件格式
   - 事件类型：process、file、network
   - 事件动作：execute、read、write、connect、open 等

3. **关系图构建** (`/api/step/graph`)
   - 从事件中提取节点（进程、文件、网络套接字）
   - 构建边（基于事件交互）
   - 去噪处理：过滤系统服务、高频边、孤立节点

4. **规则检测** (`/api/step/rules`)
   - 加载 25 条检测规则
   - 遍历事件进行规则匹配
   - 生成告警（high/medium/low 严重程度）

5. **威胁检测** (`/api/step/threat`)
   - 提取 17 维节点特征
   - Isolation Forest 异常检测
   - K-Means 行为聚类
   - 计算威胁评分并分类节点

6. **关系挖掘** (`/api/step/relations`)
   - 获取异常节点
   - 扩展 k-hop 邻居
   - 计算关联度，构建可疑子图

7. **攻击链重建** (`/api/step/chains`)
   - 识别告警节点
   - DBSCAN 聚类
   - 映射 ATT&CK 技术矩阵
   - 生成攻击报告

8. **AI 分析** (`/api/llm/analyze`)
   - 告警降噪和去重
   - 生成攻击故事叙述
   - 提取 IOC 指标
   - 生成处置建议

## API 接口

### 系统状态
- `GET /api/status` - 获取系统状态
- `POST /api/reset` - 重置系统

### 数据操作
- `POST /api/upload` - 上传日志文件
- `POST /api/generate` - 生成测试数据

### 步骤执行
- `POST /api/step/extract` - 事件提取
- `POST /api/step/graph` - 关系图构建
- `POST /api/step/rules` - 规则检测
- `POST /api/step/threat` - 威胁检测
- `POST /api/step/relations` - 关系挖掘
- `POST /api/step/chains` - 攻击链重建

### 数据获取
- `GET /api/events` - 获取事件列表（支持分页）
- `GET /api/graph` - 获取关系图数据
- `GET /api/alerts` - 获取告警列表（支持分页）
- `GET /api/threat` - 获取威胁检测结果
- `GET /api/relations` - 获取关系挖掘结果
- `GET /api/chains` - 获取攻击链结果
- `GET /api/analysis` - 获取完整分析结果
- `GET /api/scenarios` - 获取攻击场景统计
- `GET /api/logs/info` - 获取已上传日志信息
- `GET /api/cache/<step>` - 获取步骤缓存数据
- `GET /api/cache/all` - 获取所有缓存状态

### AI 分析
- `GET /api/llm/status` - 获取 LLM 服务状态
- `POST /api/llm/analyze` - 执行 AI 分析
- `GET /api/llm/result` - 获取 AI 分析结果

### 数据下载
- `GET /api/download/<file_type>` - 下载处理结果（logs/events/graph/alerts/threat/relations/chains/analysis）
- `GET /api/files` - 获取所有数据文件状态

## 前端页面

系统为单页应用，包含以下页面：

1. **数据准备** (`#page-upload`) - 上传/生成日志
2. **事件提取** (`#page-extract`) - 事件统计
3. **关系图构建** (`#page-graph`) - 图可视化（最多显示 150 节点 / 300 边）
4. **规则检测** (`#page-rules`) - 告警列表（支持分页）
5. **威胁检测** (`#page-threat`) - 节点分类、高风险节点 Top 20
6. **关系挖掘** (`#page-relations`) - 可疑关系统计
7. **攻击链重建** (`#page-chains`) - 攻击链列表
8. **AI 分析** (`#page-ai`) - AI 智能分析报告

## 检测规则

系统包含 25 条预定义检测规则，分为 5 大类：

### A. 文件异常规则 (R001-R006)
- R001: 敏感目录写入 (`/etc/`, `/boot/`, `/sys/` 等)
- R002: 临时目录可执行文件写入 (`/tmp/`, `/var/tmp/`)
- R003: 浏览器写入可执行库
- R004: 网络服务读取敏感文件
- R005: 进程删除自身可执行文件
- R006: 未知进程写入系统目录

### B. 进程异常规则 (R101-R106)
- R101: 从临时目录执行
- R102: 父子进程命名不匹配
- R103: 系统进程异常子进程
- R104: 命令行包含编码内容 (base64)
- R105: 无父进程异常
- R106: 短周期多次执行

### C. 网络异常规则 (R201-R205)
- R201: 连接非白名单境外IP
- R202: 非网络客户端建立连接
- R203: 系统进程连接非常用端口
- R204: 监听高位端口 (>1024)
- R205: 短时间多IP连接

### D. 行为序列规则 (R301-R305)
- R301: 文件下载后立即执行
- R302: 进程启动后连接外部
- R303: 读敏感文件后联网
- R304: 修改启动项
- R305: 多进程写入同一文件

### E. 时序异常规则 (R401-R403)
- R401: 凌晨异常活动 (0:00-6:00)
- R402: 周末系统操作
- R403: 频繁失败尝试

## 攻击场景

系统预设了 15 种攻击场景，可在生成测试数据时随机注入：

1. Firefox 后门植入 (T1190, T1059, T1071)
2. 供应链攻击 (T1195, T1059)
3. 权限提升 (T1068)
4. 数据窃取 (T1005, T1041)
5. 反向 Shell (T1059)
6. DLL 注入 (T1055, T1056)
7. 挖矿程序 (T1496)
8. 持久化 (T1547)
9. WebShell (T1505)
10. 内网扫描 (T1018, T1595)
11. 凭证窃取 (T1056, T1003)
12. 计划任务后门 (T1053)
13. Rootkit 加载 (T1014)
14. 中间人攻击 (T1557, T1559)
15. 容器逃逸 (T1611)

## 威胁评分等级

- **Critical (严重)**: 威胁评分 >= 0.8
- **High (高危)**: 0.6 <= 威胁评分 < 0.8
- **Medium (中危)**: 0.4 <= 威胁评分 < 0.6
- **Low (低危)**: 0.2 <= 威胁评分 < 0.4
- **Benign (正常)**: 威胁评分 < 0.2

## 数据格式

### 事件格式
```json
{
  "event_id": "evt_xxx",
  "timestamp": "2025-03-20T10:30:00Z",
  "subject": {"type": "process", "id": "proc_xxx", "name": "bash"},
  "object": {"type": "file", "id": "file_xxx", "path": "/tmp/test"},
  "action": "write",
  "label": "benign"
}
```

### 图节点格式
```json
{
  "id": "node_xxx",
  "name": "bash",
  "type": "process",
  "degree": 5
}
```

### 图边格式
```json
{
  "source": "node_xxx",
  "target": "node_yyy",
  "weight": 3
}
```

### 告警格式
```json
{
  "event_id": "evt_xxx",
  "timestamp": "2025-03-20T10:30:00Z",
  "subject": {"type": "process", "id": "proc_xxx", "name": "bash"},
  "object": {"type": "file", "id": "file_xxx", "path": "/tmp/test"},
  "action": "write",
  "rule": {
    "rule_id": "R001",
    "rule_name": "敏感目录写入",
    "severity": "high",
    "category": "file"
  },
  "message": "进程 bash 写入敏感目录 /etc/passwd",
  "severity": "high"
}
```

## 开发指南

### 添加新的检测规则

在 `modules/rule_engine.py` 中的 `RULES` 列表添加规则定义：

```python
{
    "rule_id": "RXXX",
    "rule_name": "规则名称",
    "severity": "high",  # high/medium/low
    "category": "file",   # file/process/network/sequence/temporal
    "condition": lambda e: ...  # 判断函数
}
```

### 修改 AI 分析提示词

在 `modules/llm_analyzer.py` 的 `_get_story_prompt()` 方法中修改提示词模板。

### 调整演示模式数据

演示模式的预生成数据位于 `data/demo/` 目录，可直接修改 JSON 文件。

## 参考论文

本项目基于以下论文的思想：

**SLOT: Provenance-Driven APT Detection through Graph Reinforcement Learning**
arXiv:2410.17910

## 许可证

MIT License
