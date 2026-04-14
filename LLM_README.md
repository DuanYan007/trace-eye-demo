# LLM 分析功能配置说明

## 功能概述

在规则检测完成后，可以使用大模型（OpenAI GPT）进行智能分析，包括：

1. **告警降噪**：去除重复和低质量告警
2. **攻击故事生成**：用自然语言描述攻击过程
3. **攻击阶段分析**：按 ATT&CK 框架划分攻击阶段
4. **关键发现提取**：总结最重要的发现
5. **IOC 指标提取**：提取威胁指标
6. **处置建议生成**：提供安全处置建议

## 运行模式

系统支持两种运行模式：

### 1. 演示模式（DEMO Mode）
- **特点**：无需 API Key，使用模拟数据展示分析效果
- **启用方式**：设置环境变量 `TRACE_EYE_MODE=demo`
- **适用场景**：演示、测试、无 API Key 时

### 2. 调试模式（DEBUG Mode）
- **特点**：使用真实的 OpenAI API 进行智能分析
- **启用方式**：设置环境变量 `TRACE_EYE_MODE=debug`（默认）
- **要求**：需要配置有效的 OpenAI API Key

```bash
# 使用演示模式（模拟数据）
set TRACE_EYE_MODE=demo

# 使用调试模式（真实 AI 分析）
set TRACE_EYE_MODE=debug
```

## 配置步骤（仅 DEBUG 模式需要）

### 1. 安装依赖

```bash
pip install openai
```

### 2. 配置 API Key

**方式一：环境变量（推荐）**

```bash
# Windows (CMD)
set OPENAI_API_KEY=sk-xxxxxxxxxxxxx

# Windows (PowerShell)
$env:OPENAI_API_KEY="sk-xxxxxxxxxxxxx"

# Linux/Mac
export OPENAI_API_KEY=sk-xxxxxxxxxxxxx
```

**方式二：代码配置**

在 `modules/llm_analyzer.py` 中修改：

```python
analyzer = LLMAnalyzer(api_key="sk-xxxxxxxxxxxxx")
```

### 3. 启动应用

```bash
python app.py
```

## 使用方式

### Web 界面

1. 完成规则检测后，在规则检测页面会看到「AI 智能分析」区域
2. 点击「AI 分析告警」按钮
3. 等待分析完成（通常 10-30 秒）
4. 查看生成的分析报告

### API 调用

```bash
# 检查 LLM 服务状态
curl http://localhost:5000/api/llm/status

# 执行 AI 分析
curl -X POST http://localhost:5000/api/llm/analyze

# 获取分析结果
curl http://localhost:5000/api/llm/result
```

## API 响应格式

### LLM 状态接口

```json
{
  "available": true,
  "configured": true,
  "model": "gpt-4o-mini"
}
```

### 分析结果接口

```json
{
  "success": true,
  "message": "AI 分析完成",
  "result": {
    "original_alerts_count": 156,
    "filtered_alerts_count": 45,
    "filtered_alerts": [...],
    "attack_story": {
      "summary": "检测到有组织的攻击活动...",
      "threat_level": "high",
      "attack_stages": [...],
      "attack_narrative": "攻击者通过...",
      "key_findings": [...],
      "ioc_list": [...],
      "recommendations": [...]
    },
    "analysis_report": {...},
    "recommendations": [...],
    "analyzed_at": "2025-03-20T10:30:00Z"
  },
  "progress": [
    {"value": 10, "message": "准备分析数据..."},
    {"value": 50, "message": "生成攻击叙述..."},
    ...
  ]
}
```

## 模型选择

默认使用 `gpt-4o-mini`，可在 `modules/llm_analyzer.py` 中修改：

```python
analyzer = LLMAnalyzer(model="gpt-4")  # 使用 GPT-4
analyzer = LLMAnalyzer(model="gpt-3.5-turbo")  # 使用 GPT-3.5
```

## 费用估算

- gpt-4o-mini: 约 $0.001-0.002 / 次（分析约 1000 tokens）
- gpt-4: 约 $0.01-0.03 / 次

## 故障排查

### LLM 服务不可用

1. 检查 API Key 是否正确配置
2. 检查网络连接
3. 检查 OpenAI 账户余额

### 分析结果为空

1. 确保规则检测已完成
2. 检查告警数量（告警太少可能导致分析不充分）

### 超时问题

分析默认超时时间为 120 秒，可在 `modules/llm_analyzer.py` 中修改：

```python
self.config = {
    "analysis_timeout": 180  # 增加到 180 秒
}
```

## 演示模式说明

演示模式下，系统会使用内置的模拟算法生成逼真的分析结果，无需调用真实 API：

### 模拟分析特性

1. **智能进度模拟**：模拟真实分析过程的进度更新
2. **动态攻击故事**：根据实际告警数据生成匹配的攻击叙述
3. **威胁等级评估**：根据告警数量和类型自动判定威胁等级
4. **ATT&CK 阶段划分**：自动识别攻击阶段并映射 ATT&CK 技术ID
5. **IOC 提取**：从告警中提取可疑 IP、文件、进程等指标

### 模拟数据示例

```json
{
  "llm_mode": "mock",
  "attack_story": {
    "summary": "检测到 5 条高危告警，疑似有组织的攻击活动",
    "threat_level": "high",
    "attack_stages": [
      {
        "stage": "初始访问",
        "description": "攻击者通过可疑进程获取系统访问权限",
        "techniques": ["T1564.001", "T1059"],
        "evidence": ["检测到 3 条隐藏文件相关告警"]
      },
      {
        "stage": "持久化",
        "description": "攻击者尝试修改敏感系统文件",
        "techniques": ["T1547", "T1574"],
        "evidence": ["检测到 2 条敏感文件访问告警"]
      }
    ],
    "attack_narrative": "在本次安全监控周期内，系统检测到一系列高度可疑的活动...",
    "key_findings": [
      "发现隐藏文件或可疑进程活动",
      "检测到对敏感系统文件的异常写入行为"
    ],
    "ioc_list": [
      {"type": "ip", "value": "192.168.1.100", "description": "异常网络连接"},
      {"type": "file", "value": "/etc/passwd", "description": "敏感文件访问"}
    ]
  }
}
```

### 切换到演示模式

```bash
# Windows
set TRACE_EYE_MODE=demo
python app.py

# Linux/Mac
export TRACE_EYE_MODE=demo
python app.py
```

演示模式下，分析结果会标注 `"llm_mode": "mock"`，而真实 API 分析会标注 `"llm_mode": "real"`。
