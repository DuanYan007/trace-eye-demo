# Trace-Eye Demo - APT 威胁检测系统

基于溯源图和机器学习的 APT（高级持续性威胁）检测演示系统。

## 项目简介

本项目实现了一个简化版的 APT 检测系统，展示了从原始系统日志到威胁检测的完整流程：

1. **日志生成**：模拟主机级别的系统日志（进程、文件、网络）
2. **事件提取**：将多源日志转换为统一格式
3. **图构建**：构建系统调用溯源图并去噪
4. **规则检测**：基于 25 条预定义规则进行异常检测
5. **威胁评分**：使用 Isolation Forest 和 K-Means 进行威胁评分
6. **攻击链重建**：使用聚类算法和 ATT&CK 映射重建攻击链

## 技术栈

- **后端**：Python + Flask
- **前端**：HTML + CSS + JavaScript
- **可视化**：ECharts
- **机器学习**：Isolation Forest（简化实现）、K-Means
- **数据存储**：JSON 文件

## 项目结构

```
trace-eye-demo/
├── app.py                      # Flask 主应用
├── requirements.txt            # Python 依赖
├── modules/                    # 核心处理模块
│   ├── __init__.py
│   ├── data_generator.py       # 日志数据生成器
│   ├── event_extractor.py      # 事件提取器
│   ├── graph_builder.py        # 关系图构建器
│   ├── rule_engine.py          # 规则引擎
│   ├── relation_miner.py       # 关系挖掘器
│   ├── threat_detector.py      # 威胁检测器
│   └── attack_chain_builder.py # 攻击链重建器
├── templates/
│   └── index.html              # 主页面
├── static/
│   ├── css/
│   │   └── style.css           # 样式文件
│   └── js/
│       └── main.js             # 前端逻辑
└── data/                       # 数据存储目录
    ├── data_logs.json          # 原始日志
    ├── data_graph.json         # 关系图数据
    └── data_analysis.json      # 分析结果
```

## 安装运行

### 1. 安装依赖

```bash
cd /home/duanyan/project/trace-eye-demo
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. 启动服务

```bash
python app.py
```

### 3. 访问系统

在浏览器中打开：`http://localhost:5000`

## 使用说明

### 生成测试数据

1. 点击「生成测试数据」按钮
2. 系统将生成约 4000 条模拟日志事件
3. 数据包含 15 种攻击场景

### 开始分析

1. 点击「开始分析」按钮
2. 系统将执行完整的检测流程：
   - 事件提取
   - 关系图构建
   - 规则匹配
   - 异常检测
   - 关系挖掘
   - 攻击链重建

### 查看结果

- **关系图可视化**：查看节点关系，红色为恶意，橙色为可疑
- **规则告警**：查看触发的检测规则
- **异常检测**：查看 Isolation Forest 检测结果
- **攻击链**：查看重建的攻击链和 ATT&CK 技术
- **事件日志**：查看原始事件记录

## 检测规则

系统包含 25 条预定义检测规则，分为 5 大类：

### A. 文件异常规则 (R001-R006)
- 敏感目录写入
- 临时目录可执行文件写入
- 浏览器写入可执行库
- 网络服务读取敏感文件
- 进程删除自身可执行文件
- 未知进程写入系统目录

### B. 进程异常规则 (R101-R106)
- 从临时目录执行
- 父子进程命名不匹配
- 系统进程异常子进程
- 命令行包含编码内容
- 无父进程异常
- 短周期多次执行

### C. 网络异常规则 (R201-R205)
- 连接非白名单境外IP
- 非网络客户端建立连接
- 系统进程连接非常用端口
- 监听高位端口
- 短时间多IP连接

### D. 行为序列规则 (R301-R305)
- 文件下载后立即执行
- 进程启动后连接外部
- 读敏感文件后联网
- 修改启动项
- 多进程写入同一文件

### E. 时序异常规则 (R401-R403)
- 凌晨异常活动
- 周末系统操作
- 频繁失败尝试

## 攻击场景

系统预设了 15 种攻击场景：

1. Firefox 后门植入
2. 供应链攻击
3. 权限提升
4. 数据窃取
5. 反向 Shell
6. DLL 注入
7. 挖矿程序
8. 持久化
9. WebShell
10. 内网扫描
11. 凭证窃取
12. 计划任务后门
13. Rootkit 加载
14. 中间人攻击
15. 容器逃逸

## API 接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 首页 |
| `/api/status` | GET | 获取系统状态 |
| `/api/generate` | POST | 生成测试数据 |
| `/api/analyze` | POST | 执行分析 |
| `/api/events` | GET | 获取事件列表 |
| `/api/graph` | GET | 获取关系图数据 |
| `/api/alerts` | GET | 获取告警列表 |
| `/api/analysis` | GET | 获取完整分析结果 |
| `/api/scenarios` | GET | 获取攻击场景 |
| `/api/reset` | POST | 重置系统 |

## 参考论文

本项目基于以下论文的思想：

**SLOT: Provenance-Driven APT Detection through Graph Reinforcement Learning**
arXiv:2410.17910

## 许可证

MIT License
