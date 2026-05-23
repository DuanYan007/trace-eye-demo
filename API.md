# Trace-Eye Demo API 文档

## 基础信息

- **Base URL**: `http://localhost:5000`
- **Content-Type**: `application/json`

## 接口列表

### LLM 配置与测试

大模型配置从项目根目录 `.env` 读取：

```env
TRACE_EYE_MODE=debug
LLM_PROVIDER=deepseek
DEEPSEEK_API_KEY=你的 DeepSeek API Key
DEEPSEEK_API_BASE=https://api.deepseek.com
LLM_MODEL=deepseek-v4
```

#### 获取 LLM 状态

```http
GET /api/llm/status
```

#### 测试 LLM 连接

```http
POST /api/llm/test
Content-Type: application/json

{
  "model": "deepseek-v4"
}
```

#### 生成 AI 分析报告

```http
POST /api/llm/analyze
Content-Type: application/json

{
  "model": "deepseek-v4"
}
```

说明：生成报告前需要先完成威胁检测、关系挖掘和攻击链重建。

### 1. 获取系统状态

获取当前系统运行状态。

**请求**
```
GET /api/status
```

**响应**
```json
{
  "status": "idle|generating|analyzing",
  "progress": 0-100,
  "message": "状态描述",
  "last_generated": "ISO 8601 时间戳",
  "last_analyzed": "ISO 8601 时间戳"
}
```

---

### 2. 生成测试数据

生成模拟的系统日志数据。

**请求**
```
POST /api/generate
Content-Type: application/json

{
  "total_events": 4000  // 可选，默认4000
}
```

**响应**
```json
{
  "success": true,
  "message": "数据生成完成",
  "statistics": {
    "total_events": 4000,
    "attack_events": 600,
    "benign_events": 3400,
    "entity_count": 150,
    "scenario_count": 12
  }
}
```

---

### 3. 执行分析

执行完整的威胁检测分析流程。

**请求**
```
POST /api/analyze
```

**响应**
```json
{
  "success": true,
  "message": "分析完成",
  "summary": {
    "threat_level": "high",
    "high_risk_nodes": 15,
    "total_alerts": 45
  }
}
```

---

### 4. 获取事件列表

获取系统事件列表（支持分页）。

**请求**
```
GET /api/events?limit=100&offset=0
```

**参数**
| 参数 | 类型 | 说明 |
|------|------|------|
| limit | int | 每页数量，默认100 |
| offset | int | 偏移量，默认0 |

**响应**
```json
{
  "total": 4000,
  "offset": 0,
  "limit": 100,
  "events": [
    {
      "event_id": "evt_00001",
      "timestamp": "2025-03-20T10:30:15.123Z",
      "subject": {
        "type": "process",
        "id": "proc_1234",
        "name": "firefox",
        "pid": 2345
      },
      "object": {
        "type": "file",
        "id": "file_456",
        "path": "/tmp/dragon"
      },
      "action": "write",
      "log_type": "file",
      "label": "malicious"
    }
  ]
}
```

---

### 5. 获取关系图数据

获取用于可视化的关系图数据。

**请求**
```
GET /api/graph
```

**响应**
```json
{
  "nodes": [
    {
      "id": "proc_1234",
      "name": "firefox",
      "type": "process",
      "label": "benign",
      "degree": 5
    }
  ],
  "edges": [
    {
      "id": "proc_1234->file_456",
      "source": "proc_1234",
      "target": "file_456",
      "action": "write",
      "weight": 1,
      "label": "benign"
    }
  ],
  "statistics": {
    "node_count": 150,
    "edge_count": 450,
    "avg_degree": 3.0,
    "density": 0.02
  }
}
```

---

### 6. 获取告警列表

获取规则检测的告警列表。

**请求**
```
GET /api/alerts?limit=50
```

**参数**
| 参数 | 类型 | 说明 |
|------|------|------|
| limit | int | 返回数量，默认50 |

**响应**
```json
{
  "total": 45,
  "alerts": [
    {
      "event_id": "evt_00123",
      "timestamp": "2025-03-20T10:30:15.123Z",
      "rule": {
        "rule_id": "R001",
        "rule_name": "敏感目录写入",
        "category": "file",
        "severity": "high",
        "description": "非root进程写入/etc敏感目录",
        "technique": "T1222"
      },
      "subject": {...},
      "object": {...}
    }
  ]
}
```

---

### 7. 获取完整分析结果

获取完整的威胁检测结果。

**请求**
```
GET /api/analysis
```

**响应**
```json
{
  "analysis_id": "analysis_1711234567",
  "analyzed_at": "2025-03-20T10:05:00.000Z",
  "events_statistics": {
    "total_events": 4000,
    "graph_nodes": 150,
    "graph_edges": 450
  },
  "rule_detection": {
    "total_alerts": 45,
    "by_severity": {
      "high": 12,
      "medium": 20,
      "low": 13
    },
    "by_category": {
      "file": 15,
      "process": 18,
      "network": 12
    },
    "alerts": [...]
  },
  "threat_detection": {
    "anomaly_nodes": ["proc_9001", "file_456"],
    "classified_nodes": {
      "critical": [],
      "high": ["proc_9001"],
      "medium": ["file_456"],
      "low": [...],
      "benign": [...]
    },
    "summary": {
      "total_nodes": 150,
      "critical_count": 0,
      "high_count": 5,
      "medium_count": 12,
      "overall_threat_level": "high"
    }
  },
  "relation_mining": {
    "total_relations": 25,
    "total_subgraphs": 3,
    "suspicious_subgraphs": [...]
  },
  "attack_chains": {
    "total_chains": 3,
    "by_attack_type": {
      "后门通信": 1,
      "数据窃取": 1,
      "权限提升": 1
    },
    "top_techniques": [
      ["T1071", 15],
      ["T1059", 12],
      ["T1105", 8]
    ],
    "chains": [...]
  },
  "overall_assessment": {
    "threat_level": "high",
    "high_risk_nodes": 17,
    "total_alerts": 45
  }
}
```

---

### 8. 获取攻击场景

获取预设的攻击场景列表。

**请求**
```
GET /api/scenarios
```

**响应**
```json
{
  "scenarios": [
    {
      "scenario": {
        "id": "scen_001",
        "name": "Firefox后门植入",
        "type": "backdoor",
        "description": "通过Firefox漏洞下载恶意文件并执行后门",
        "techniques": ["T1190", "T1059", "T1071"]
      },
      "event_count": 45
    }
  ]
}
```

---

### 9. 重置系统

清除所有数据，重置系统状态。

**请求**
```
POST /api/reset
```

**响应**
```json
{
  "success": true,
  "message": "系统已重置"
}
```

---

## 错误响应

所有错误响应格式：

```json
{
  "error": "错误描述信息"
}
```

常见 HTTP 状态码：
- `200` - 成功
- `400` - 请求参数错误
- `404` - 资源不存在
- `500` - 服务器内部错误
