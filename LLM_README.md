# LLM 分析功能配置说明

## DeepSeek 快速配置

项目根目录已经提供 `.env.example`，实际运行时请使用根目录 `.env`：

```env
TRACE_EYE_MODE=debug
LLM_PROVIDER=deepseek
DEEPSEEK_API_KEY=你的 DeepSeek API Key
DEEPSEEK_API_BASE=https://api.deepseek.com
LLM_MODEL=deepseek-v4
```

说明：

- `DEEPSEEK_API_KEY` 由你自己填写，不要提交到 Git。
- `.env` 已被 `.gitignore` 忽略。
- `TRACE_EYE_MODE=debug` 才会调用真实 LLM；`demo` 模式会使用模拟分析。
- 可双击 `run_deepseek.bat` 启动，也可以直接运行 `python app.py`。
- AI 分析页面顶部提供“模型名称”和“测试连接”，可在生成报告前确认模型是否可访问。

## 功能概述

在规则检测完成后，可以使用大模型（默认 DeepSeek，也兼容 OpenAI 风格接口）进行智能分析，包括：

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
- **特点**：使用真实的 DeepSeek API 进行智能分析
- **启用方式**：设置环境变量 `TRACE_EYE_MODE=debug`（默认）
- **要求**：需要配置有效的 DeepSeek API Key

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

**方式一：`.env` 文件（推荐）**

项目根目录 `.env` 已经准备好，只需要填写：

```env
DEEPSEEK_API_KEY=你的 DeepSeek API Key
```

**方式二：环境变量**

```bash
# Windows (CMD)
set DEEPSEEK_API_KEY=sk-xxxxxxxxxxxxx

# Windows (PowerShell)
$env:DEEPSEEK_API_KEY="sk-xxxxxxxxxxxxx"

# Linux/Mac
export DEEPSEEK_API_KEY=sk-xxxxxxxxxxxxx
```

**方式三：代码配置**

在 `modules/llm_analyzer.py` 中修改：

```python
analyzer = LLMAnalyzer(api_key="sk-xxxxxxxxxxxxx")
```

### 3. 启动应用

```bash
python app.py
```

或双击：

```bash
run_deepseek.bat
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
  "provider": "deepseek",
  "model": "deepseek-v4",
  "mode": "real"
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

默认使用 `.env` 中的 `LLM_MODEL=deepseek-v4`。也可以在 AI 分析页面顶部直接修改模型名称并点击“测试连接”。

如果需要切回其他兼容接口，可调整 `.env` 中的 `LLM_PROVIDER`、`*_API_BASE` 和 `LLM_MODEL`。

## 费用估算

- 费用取决于 DeepSeek 当前计费规则和实际输入/输出 token 数。
- 建议先在 AI 页面使用“测试连接”，再生成完整报告。

## 故障排查

### LLM 服务不可用

1. 检查 API Key 是否正确配置
2. 检查网络连接
3. 检查 DeepSeek 账户余额和模型名称是否可用

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
