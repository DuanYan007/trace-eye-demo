# Trace-Eye Demo - APT 威胁检测系统

基于溯源图和机器学习的 APT（高级持续性威胁）检测演示系统。

## 项目简介

本项目实现了一个完整的 APT 检测演示系统，展示了从原始系统日志到威胁检测的完整分析流程：

1. **数据准备**：支持上传日志文件或生成模拟攻击场景数据
2. **事件提取**：将多源日志（进程、文件、网络）转换为统一事件格式
3. **图构建**：构建系统调用溯源图，自动去噪过滤
4. **规则检测**：基于 25 条预定义规则进行异常检测
5. **威胁评分**：使用 Isolation Forest 和 K-Means 进行威胁评分和分类
6. **关系挖掘**：挖掘威胁节点的辐射关系和可疑子图
7. **攻击链重建**：使用 DBSCAN 聚类和 ATT&CK 框架映射重建攻击链
8. **AI 分析**：基于大模型的告警降噪与攻击故事生成

## 技术栈

- **后端**：Python 3.8+ + Flask
- **前端**：原生 HTML/CSS/JavaScript（单页应用架构）
- **可视化**：ECharts 5.4.3
- **机器学习**：Isolation Forest、K-Means、DBSCAN
- **数据存储**：JSON 文件

## DeepSeek LLM 配置

真实大模型分析从项目根目录 `.env` 读取配置。你只需要把自己的 Key 填到 `DEEPSEEK_API_KEY`：

```env
TRACE_EYE_MODE=debug
LLM_PROVIDER=deepseek
DEEPSEEK_API_KEY=你的 DeepSeek API Key
DEEPSEEK_API_BASE=https://api.deepseek.com
LLM_MODEL=deepseek-v4
```

`.env` 已在 `.gitignore` 中忽略，不会提交到仓库。配置完成后可运行 `run_deepseek.bat` 或 `python app.py`，然后在 AI 分析页面使用“测试连接”确认模型可访问。

## 项目结构

```
trace-eye-demo/
├── app.py                      # Flask 主应用入口
├── main.py                     # 备用启动入口
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
│   │   ├── style.css           # 主样式文件
│   │   └── components.css      # 组件样式
│   ├── js/
│   │   ├── main.js             # 前端主逻辑
│   │   ├── utils/              # 工具模块
│   │   │   ├── api.js          # API 请求封装
│   │   │   ├── data-cache.js   # 数据缓存管理
│   │   │   └── component-loader.js  # 组件动态加载器
│   │   └── components/         # 页面组件
│   │       ├── upload.js       # 数据准备
│   │       ├── extract.js      # 事件提取
│   │       ├── graph.js        # 关系图构建
│   │       ├── rules.js        # 规则检测
│   │       ├── threat.js       # 威胁检测
│   │       ├── relations.js    # 关系挖掘
│   │       ├── chains.js       # 攻击链重建
│   │       └── ai.js           # AI 分析
│   └── components/             # HTML 组件模板
│       ├── upload.html
│       ├── extract.html
│       ├── graph.html
│       ├── rules.html
│       ├── threat.html
│       ├── relations.html
│       ├── chains.html
│       └── ai.html
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
└── CLAUDE.md                   # 开发指南
```

## 运行模式

系统支持两种运行模式，通过环境变量 `TRACE_EYE_MODE` 控制：

### DEMO 模式（默认，推荐用于演示）

```bash
export TRACE_EYE_MODE=demo
# Windows: set TRACE_EYE_MODE=demo
python app.py
```

- 使用预生成的 JSON 数据直接展示
- 每个步骤需要手动执行（点击按钮）
- 数据已预加载到内存，响应速度快
- 适合演示和展示

### DEBUG 模式（开发调试）

```bash
export TRACE_EYE_MODE=debug
python app.py
```

- 使用真实算法处理数据
- 支持上传日志文件或生成测试数据
- 每个步骤需要手动执行
- 适合开发和调试

## 安装运行

### 1. 安装依赖

```bash
cd trace-eye-demo
pip install -r requirements.txt
```

### 2. 启动服务

```bash
python app.py
```

### 3. 访问系统

在浏览器中打开：`http://localhost:5000`

## 使用说明

### DEMO 模式操作流程

1. **开始演示**：点击「开始演示」按钮，系统准备数据
2. **逐步分析**：依次点击各页面的「开始XXX」按钮执行分析步骤
3. **查看结果**：每步完成后可查看对应的可视化结果和数据统计

### 页面功能说明

| 页面 | 功能 | 主要输出 |
|------|------|----------|
| 数据准备 | 上传日志或生成测试数据 | 原始日志文件 |
| 事件提取 | 解析多源日志为统一事件格式 | 事件统计、类型分布 |
| 关系图构建 | 构建系统调用溯源图 | 图可视化（节点/边） |
| 规则检测 | 基于25条规则匹配异常 | 告警列表、严重程度分布 |
| 威胁检测 | Isolation Forest + K-Means 聚类 | 威胁等级分类、高风险节点 |
| 关系挖掘 | 挖掘威胁节点的辐射关系 | 威胁节点列表、关系网络图 |
| 攻击链重建 | DBSCAN 聚类 + ATT&CK 映射 | 攻击链列表、森林可视化 |
| AI 分析 | 告警降噪与攻击故事生成 | 分析报告、IOC 指标 |

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

## 前端架构

系统采用单页应用（SPA）架构：

- **组件化设计**：每个页面独立为 HTML + JS 组件
- **动态加载**：按需加载组件，减少初始加载时间
- **数据缓存**：前端 DataCache 实现数据缓存，减少 API 请求
- **响应式布局**：支持桌面端和大屏显示

## 参考论文

本项目基于以下论文的思想：

**SLOT: Provenance-Driven APT Detection through Graph Reinforcement Learning**
arXiv:2410.17910

## 许可证

MIT License
