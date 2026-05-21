# -*- coding: utf-8 -*-
"""
大模型告警分析模块
基于 OpenAI GPT 进行告警分析、降噪和攻击故事生成
支持模拟模式（不调用真实 API）
"""

import os
import json
import asyncio
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime
import random

try:
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False
    openai = None


class LLMAnalyzer:
    """大模型告警分析器"""

    def __init__(self, api_key: str = None, model: str = None, use_mock: bool = None):
        """
        初始化 LLM 分析器

        Args:
            api_key: OpenAI API Key，如果不提供则从环境变量读取
            model: 使用的模型名称，默认 gpt-4o-mini
            use_mock: 强制使用模拟模式，None 则自动检测
        """
        self._load_env_file()
        self.provider = os.environ.get("LLM_PROVIDER", "openai").lower()
        default_model = "deepseek-v4-pro" if self.provider == "deepseek" else "gpt-4o-mini"
        self.model = os.environ.get("LLM_MODEL", model or default_model)

        if self.provider == "deepseek":
            self.api_key = api_key or os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("OPENAI_API_KEY")
            self.api_base = os.environ.get("DEEPSEEK_API_BASE") or os.environ.get("OPENAI_API_BASE") or "https://api.deepseek.com"
        else:
            self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
            self.api_base = os.environ.get("OPENAI_API_BASE") or None
        self.client = None
        self.use_mock = use_mock

        # 自动检测是否使用模拟模式（与 app.py 保持一致，默认为 demo）
        if self.use_mock is None:
            # 如果没有 API Key 或者设置了 DEMO_MODE，则使用模拟模式
            demo_mode = os.environ.get("TRACE_EYE_MODE", "demo").lower() == "demo"
            self.use_mock = (not self.api_key) or demo_mode

        if not self.use_mock and HAS_OPENAI and self.api_key:
            try:
                client_kwargs = {"api_key": self.api_key}
                if self.api_base:
                    client_kwargs["base_url"] = self.api_base
                self.client = openai.AsyncOpenAI(**client_kwargs)
            except:
                print("OpenAI 连接失败，切换到模拟模式")
                self.use_mock = True
        else:
            self.use_mock = True

        # 分析配置
        self.config = {
            "max_tokens": 2000,
            "temperature": 0.3,
            "enable_streaming": True,
            "analysis_timeout": 120  # 超时时间(秒)
        }

    def _load_env_file(self):
        """Load simple KEY=value pairs from project .env without requiring python-dotenv."""
        env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
        if not os.path.exists(env_path):
            return

        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    if key and key not in os.environ:
                        os.environ[key] = value
        except Exception as exc:
            print(f"读取 .env 失败: {exc}")

    def is_available(self) -> bool:
        """检查 LLM 服务是否可用（模拟模式下始终返回 True）"""
        if self.use_mock:
            return True
        return HAS_OPENAI and self.client is not None

    async def analyze_alerts(
        self,
        alerts: List[Dict],
        graph: Dict,
        events: List[Dict],
        progress_callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        分析告警列表

        Args:
            alerts: 规则检测产生的告警列表
            graph: 关系图数据
            events: 原始事件列表
            progress_callback: 进度回调函数

        Returns:
            分析结果，包含降噪后的告警、攻击故事等
        """
        # 模拟模式：直接返回预设的分析结果
        if self.use_mock:
            return await self._simulate_analysis(alerts, progress_callback)

        if progress_callback:
            await progress_callback(10, "准备分析数据...")

        # 1. 告警降噪和分组
        deduped_alerts = await self._deduplicate_alerts(alerts, graph)

        if progress_callback:
            await progress_callback(30, "分析告警关联性...")

        # 2. 按严重程度分组
        high_priority_alerts = [a for a in deduped_alerts if a.get("severity") == "high"]
        medium_priority_alerts = [a for a in deduped_alerts if a.get("severity") == "medium"]

        # 3. 生成攻击故事
        attack_story = await self._generate_attack_story(
            high_priority_alerts[:20],  # 限制输入数量
            graph,
            events,
            progress_callback
        )

        # 4. 生成分析报告
        report = await self._generate_analysis_report(
            deduped_alerts,
            attack_story,
            progress_callback
        )

        if progress_callback:
            await progress_callback(100, "分析完成")

        return self._finalize_report({
            "original_alerts_count": len(alerts),
            "filtered_alerts_count": len(deduped_alerts),
            "filtered_alerts": deduped_alerts[:100],  # 返回前100条
            "attack_story": attack_story,
            "analysis_report": report,
            "recommendations": self._generate_recommendations(attack_story),
            "analyzed_at": datetime.now().isoformat() + "Z",
            "llm_mode": "real"
        })

    async def _deduplicate_alerts(self, alerts: List[Dict], graph: Dict) -> List[Dict]:
        """告警降噪：去除重复和低质量告警"""
        # 简化实现：按主体和动作去重
        seen = set()
        deduped = []

        for alert in alerts:
            subject_id = alert.get("subject", {}).get("id", "")
            action = alert.get("action", "")
            key = f"{subject_id}:{action}"

            # 保留高危告警
            severity = alert.get("rule", {}).get("severity", "low")
            if severity == "high" and key not in seen:
                deduped.append({
                    "id": alert.get("event_id", ""),
                    "subject": alert.get("subject", {}),
                    "object": alert.get("object", {}),
                    "action": action,
                    "rule": alert.get("rule", {}),
                    "severity": severity,
                    "message": alert.get("message", ""),
                    "timestamp": alert.get("timestamp", "")
                })
                seen.add(key)

        return deduped

    async def _generate_attack_story(
        self,
        alerts: List[Dict],
        graph: Dict,
        events: List[Dict],
        progress_callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """生成攻击故事"""
        if not alerts:
            return {"summary": "未检测到高危告警", "narrative": "", "chains": []}

        if progress_callback:
            await progress_callback(50, "生成攻击叙述...")

        # 构建上下文信息
        context = self._build_context(alerts, graph, events)

        # 调用 LLM 生成故事
        prompt = self._get_story_prompt(context)

        try:
            response = await self._call_llm(prompt)
            return self._parse_story_response(response, alerts)
        except Exception as e:
            print(f"LLM 调用失败: {e}")
            return self._generate_fallback_story(alerts, context)

    async def _generate_analysis_report(
        self,
        alerts: List[Dict],
        attack_story: Dict,
        progress_callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """生成分析报告"""
        if progress_callback:
            await progress_callback(80, "生成分析报告...")

        severity_counts = {}
        for alert in alerts:
            sev = alert.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "severity_summary": severity_counts,
            "total_filtered": len(alerts),
            "attack_types": self._extract_attack_types(alerts),
            "affected_assets": self._extract_affected_assets(alerts),
            "timeline": self._build_timeline(alerts)
        }

    def _build_context(self, alerts: List[Dict], graph: Dict, events: List[Dict]) -> str:
        """构建 LLM 上下文"""
        # 提取关键信息
        high_alerts = [a for a in alerts if a.get("severity") == "high"][:10]

        context_parts = [
            f"检测到 {len(alerts)} 条经过降噪后的告警",
            f"其中高危告警 {len(high_alerts)} 条",
            ""
        ]

        # 添加高危告警详情
        for i, alert in enumerate(high_alerts, 1):
            rule_name = alert.get("rule", {}).get("rule_name", "未知规则")
            subject = alert.get("subject", {}).get("name", "未知进程")
            obj = alert.get("object", {})
            obj_info = obj.get("name", "") or obj.get("path", "") or obj.get("ip", "")
            timestamp = alert.get("timestamp", "")[:16]

            context_parts.append(
                f"{i}. [{timestamp}] {rule_name}\n"
                f"   主体: {subject}\n"
                f"   客体: {obj_info}\n"
            )

        return "\n".join(context_parts)

    def _get_story_prompt(self, context: str) -> str:
        """获取攻击故事生成的提示词"""
        return f"""你是一个网络安全分析专家，需要分析以下系统告警数据，生成一份清晰的攻击分析报告。

## 告警数据
{context}

## 任务要求

请基于以上告警数据，生成一份 JSON 格式的分析报告，包含以下字段：

{{
  "summary": "用2-3句话概括整体威胁状况",
  "threat_level": "评估威胁等级 (critical/high/medium/low)",
  "attack_stages": [
    {{
      "stage": "阶段名称（如：初始访问、持久化、权限提升等）",
      "description": "该阶段的详细描述",
      "techniques": ["使用的攻击技术ID（如T1059）"],
      "evidence": ["支持该阶段的关键证据"]
    }}
  ],
  "attack_narrative": "用连贯的叙述性文字描述整个攻击过程，让非技术人员也能理解",
  "key_findings": [
    "发现1：具体的发现内容",
    "发现2：具体的发现内容"
  ],
  "ioc_list": [
    {{"type": "ip", "value": "可疑IP地址", "description": "描述"}},
    {{"type": "file", "value": "可疑文件路径", "description": "描述"}}
  ],
  "recommendations": [
    "紧急处置建议1",
    "后续处置建议2"
  ]
}}

请只返回 JSON，不要包含其他说明文字。"""

    async def _call_llm(self, prompt: str) -> str:
        """调用 LLM API"""
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "你是一个专业的网络安全分析专家，擅长分析系统告警并生成清晰的威胁报告。"},
                {"role": "user", "content": prompt}
            ],
            max_tokens=self.config["max_tokens"],
            temperature=self.config["temperature"]
        )
        return response.choices[0].message.content

    def _parse_story_response(self, response: str, alerts: List[Dict]) -> Dict:
        """解析 LLM 响应"""
        try:
            # 尝试解析 JSON
            # 移除可能的 markdown 代码块标记
            response = response.strip()
            if response.startswith("```"):
                response = response.split("```")[1]
                if response.startswith("json"):
                    response = response[4:]
                response = response.strip()
            if response.endswith("```"):
                response = response.rsplit("```", 1)[0].strip()

            return json.loads(response)
        except:
            # 解析失败，返回简化版
            return self._generate_fallback_story(alerts, response)

    def _generate_fallback_story(self, alerts: List[str], context: str) -> Dict:
        """生成备用故事（当 LLM 调用失败时）"""
        return {
            "summary": f"检测到 {len(alerts)} 条告警，需要进一步人工分析",
            "threat_level": "high" if len(alerts) > 10 else "medium",
            "attack_stages": [
                {
                    "stage": "异常检测",
                    "description": "系统检测到多个可疑行为模式",
                    "techniques": [],
                    "evidence": [f"{len(alerts)} 条规则告警"]
                }
            ],
            "attack_narrative": f"系统在安全监控中发现 {len(alerts)} 条告警。这些告警涉及文件访问异常、进程行为可疑和网络连接异常等多个方面。建议安全团队对相关告警进行进一步调查。",
            "key_findings": [
                f"共触发 {len(alerts)} 条告警规则",
                "告警涉及多个系统层面（文件、进程、网络）"
            ],
            "ioc_list": [],
            "recommendations": [
                "立即审查高危告警涉及的主机和账户",
                "隔离受影响系统以防进一步损害",
                "收集更多审计日志进行深入分析"
            ]
        }

    def _extract_attack_types(self, alerts: List[Dict]) -> List[str]:
        """提取攻击类型"""
        types = set()
        for alert in alerts:
            rule_name = alert.get("rule", {}).get("rule_name", "")
            if "后门" in rule_name:
                types.add("后门植入")
            elif "提权" in rule_name:
                types.add("权限提升")
            elif "数据" in rule_name or "窃取" in rule_name:
                types.add("数据窃取")
            elif "注入" in rule_name:
                types.add("代码注入")
            elif "网络" in rule_name or "连接" in rule_name:
                types.add("网络通信")
        return list(types)

    def _extract_affected_assets(self, alerts: List[Dict]) -> List[Dict]:
        """提取受影响资产"""
        assets = {}
        for alert in alerts:
            subject = alert.get("subject", {})
            obj = alert.get("object", {})

            # 进程资产
            proc_name = subject.get("name", "")
            if proc_name and proc_name not in assets:
                assets[proc_name] = {"type": "process", "name": proc_name, "alert_count": 0}
            if proc_name in assets:
                assets[proc_name]["alert_count"] += 1

            # 文件资产
            file_path = obj.get("path", "")
            if file_path and file_path not in assets:
                assets[file_path] = {"type": "file", "name": file_path, "alert_count": 0}
            if file_path in assets:
                assets[file_path]["alert_count"] += 1

        return sorted(assets.values(), key=lambda x: x["alert_count"], reverse=True)[:20]

    def _build_timeline(self, alerts: List[Dict]) -> List[Dict]:
        """构建时间线"""
        timeline = []
        for alert in sorted(alerts, key=lambda x: x.get("timestamp", ""))[:15]:
            timeline.append({
                "timestamp": alert.get("timestamp", ""),
                "rule": alert.get("rule", {}).get("rule_name", ""),
                "subject": alert.get("subject", {}).get("name", ""),
                "description": alert.get("message", "")[:100]
            })
        return timeline

    def _generate_recommendations(self, story: Dict) -> List[str]:
        """生成处置建议"""
        recommendations = []

        threat_level = story.get("threat_level", "low")
        if threat_level in ["critical", "high"]:
            recommendations.extend([
                "立即隔离受影响主机",
                "保存现场证据（内存转储、日志备份）",
                "通知安全团队进行深入调查",
                "检查相关账户的异常活动"
            ])
        elif threat_level == "medium":
            recommendations.extend([
                "在24小时内完成调查",
                "加强相关系统的监控",
                "审查相关访问日志"
            ])

        # 根据 IOC 生成建议
        iocs = story.get("ioc_list", [])
        if iocs:
            recommendations.append("将 IOC 指标加入安全监控设备黑名单")

        return recommendations

    async def _simulate_analysis(
        self,
        alerts: List[Dict],
        progress_callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        模拟 AI 分析（演示模式）
        返回预设的逼真分析结果，无需调用真实 API
        """
        # 模拟处理进度
        if progress_callback:
            await progress_callback(10, "准备分析数据...")
            await asyncio.sleep(0.3)

            await progress_callback(30, "分析告警关联性...")
            await asyncio.sleep(0.4)

            await progress_callback(50, "生成攻击叙述...")
            await asyncio.sleep(0.5)

            await progress_callback(70, "提取 IOC 指标...")
            await asyncio.sleep(0.3)

            await progress_callback(90, "生成处置建议...")
            await asyncio.sleep(0.2)

            await progress_callback(100, "分析完成")

        # 分析告警数据
        high_alerts = [a for a in alerts if a.get("severity") == "high" or a.get("rule", {}).get("severity") == "high"]
        medium_alerts = [a for a in alerts if a.get("severity") == "medium" or a.get("rule", {}).get("severity") == "medium"]

        # 根据告警数量和类型生成逼真的攻击故事
        attack_story = self._generate_mock_attack_story(alerts, high_alerts)

        # 生成分析报告
        report = {
            "severity_summary": {
                "critical": len([a for a in high_alerts if a.get("rule", {}).get("severity") == "critical"]),
                "high": len(high_alerts),
                "medium": len(medium_alerts),
                "low": len(alerts) - len(high_alerts) - len(medium_alerts)
            },
            "total_filtered": len(alerts),
            "attack_types": self._extract_attack_types(alerts),
            "affected_assets": self._extract_affected_assets(alerts),
            "timeline": self._build_timeline(alerts)
        }

        # 生成处置建议
        recommendations = self._generate_recommendations(attack_story)

        return self._finalize_report({
            "original_alerts_count": len(alerts),
            "filtered_alerts_count": len(alerts),
            "filtered_alerts": alerts[:100],
            "attack_story": attack_story,
            "analysis_report": report,
            "recommendations": recommendations,
            "analyzed_at": datetime.now().isoformat() + "Z",
            "llm_mode": "mock"
        })

    def _finalize_report(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Add Markdown report sections and manual-review guidance."""
        story = result.get("attack_story", {}) or {}
        report = result.get("analysis_report", {}) or {}
        recommendations = result.get("recommendations") or story.get("recommendations") or []
        iocs = story.get("ioc_list") or story.get("iocs") or []
        stages = story.get("attack_stages") or []
        findings = story.get("key_findings") or []
        severity = report.get("severity_summary") or {}

        result["statistics"] = {
            "original_alerts": result.get("original_alerts_count", 0),
            "filtered_alerts": result.get("filtered_alerts_count", report.get("total_filtered", 0))
        }

        result["diagnosis_markdown"] = "\n".join([
            "# 系统诊断报告",
            "",
            "## 总体判断",
            f"- 威胁等级: **{story.get('threat_level', 'unknown')}**",
            f"- 摘要: {story.get('summary') or story.get('threat_summary') or '暂无摘要'}",
            f"- 原始告警: **{result.get('original_alerts_count', 0)}**",
            f"- 降噪后告警: **{result.get('filtered_alerts_count', 0)}**",
            "",
            "## 告警严重度",
            f"- Critical: **{severity.get('critical', 0)}**",
            f"- High: **{severity.get('high', 0)}**",
            f"- Medium: **{severity.get('medium', 0)}**",
            f"- Low: **{severity.get('low', 0)}**",
            "",
            "## 系统存在的问题",
            *(self._markdown_bullets(findings) or ["- 未提取到明确关键发现，建议人工检查原始告警与攻击链。"]),
            "",
            "## 攻击阶段与证据",
            *(self._markdown_stages(stages) or ["- 暂无明确攻击阶段。"]),
            "",
            "## IOC 指标",
            *(self._markdown_iocs(iocs) or ["- 暂无可提取 IOC。"]),
            "",
            "## 攻击叙述",
            story.get("attack_narrative") or "暂无攻击叙述。"
        ])

        result["remediation_markdown"] = "\n".join([
            "# 系统修复建议",
            "",
            "## 立即处置",
            *(self._markdown_bullets(recommendations) or [
                "- 隔离受影响主机，防止横向移动。",
                "- 冻结可疑账户并轮换关联凭据。",
                "- 备份日志、进程、网络连接和可疑文件样本。"
            ]),
            "",
            "## 按攻击阶段修复",
            *(self._markdown_stage_remediation(stages) or [
                "- 对告警涉及的主机、进程、文件和网络连接进行人工复核。",
                "- 将真实威胁沉淀为检测规则，将误报沉淀为白名单。"
            ]),
            "",
            "## IOC 封禁与监控",
            *(self._markdown_ioc_remediation(iocs) or ["- 暂无 IOC 时，应基于高危告警主体补充主机级排查。"]),
            "",
            "## 后续加固",
            "- 补充检测规则和应急响应剧本。",
            "- 对关键资产开启更高等级日志留存。",
            "- 完成修复后执行二次分析，确认告警下降。"
        ])

        threat_level = story.get("threat_level", "unknown")
        original_alerts = result.get("original_alerts_count", 0)
        review_required = threat_level in ["critical", "high", "unknown"] or original_alerts >= 20
        result["manual_review"] = {
            "required": review_required,
            "title": "建议人工复核" if review_required else "可抽样复核",
            "reason": (
                "LLM 判断存在较高风险或告警数量较多，建议安全分析师确认攻击链、IOC 和修复优先级。"
                if review_required
                else "当前风险较低，可由分析师抽样确认后归档。"
            )
        }

        return result

    def _markdown_bullets(self, items: List[Any]) -> List[str]:
        return [f"- {item}" for item in items if item]

    def _markdown_stages(self, stages: List[Dict]) -> List[str]:
        lines = []
        for index, stage in enumerate(stages, 1):
            if not isinstance(stage, dict):
                lines.append(f"{index}. **攻击阶段**: {stage}")
                continue
            lines.append(f"{index}. **{stage.get('stage', '未命名阶段')}**: {stage.get('description', '暂无描述')}")
            for evidence in stage.get("evidence", [])[:3]:
                lines.append(f"   - 证据: {evidence}")
            techniques = stage.get("techniques", [])
            if techniques:
                lines.append(f"   - 技术: {', '.join(techniques)}")
        return lines

    def _markdown_iocs(self, iocs: List[Dict]) -> List[str]:
        lines = []
        for ioc in iocs:
            if isinstance(ioc, dict):
                lines.append(f"- `{ioc.get('type', 'unknown')}`: {ioc.get('value', '-')} - {ioc.get('description', '暂无描述')}")
            else:
                lines.append(f"- `{ioc}`")
        return lines

    def _markdown_stage_remediation(self, stages: List[Dict]) -> List[str]:
        lines = []
        for stage in stages:
            if not isinstance(stage, dict):
                continue
            name = stage.get("stage", "异常阶段")
            lines.append(f"- **{name}**: 复核该阶段关联证据，隔离受影响资产，并补充对应检测规则。")
        return lines

    def _markdown_ioc_remediation(self, iocs: List[Dict]) -> List[str]:
        lines = []
        for ioc in iocs:
            if isinstance(ioc, dict):
                lines.append(f"- 将 `{ioc.get('value', '-')}` 加入 {ioc.get('type', 'IOC')} 监控或阻断列表。")
            else:
                lines.append(f"- 将 `{ioc}` 加入 IOC 监控或阻断列表。")
        return lines

    def _generate_mock_attack_story(self, all_alerts: List[Dict], high_alerts: List[Dict]) -> Dict[str, Any]:
        """生成模拟的攻击故事"""
        alert_count = len(all_alerts)
        high_count = len(high_alerts)

        # 根据告警特征确定威胁等级
        if high_count >= 10:
            threat_level = "critical"
            summary = "检测到高度组织化的APT攻击活动，攻击者已建立持久化后门并进行横向移动"
        elif high_count >= 5:
            threat_level = "high"
            summary = f"检测到 {high_count} 条高危告警，疑似有组织的攻击活动"
        elif high_count >= 2:
            threat_level = "medium"
            summary = f"检测到 {high_count} 条高危告警，需要关注"
        else:
            threat_level = "low"
            summary = "检测到少量异常行为，建议持续关注"

        # 提取攻击阶段
        attack_stages = []
        key_findings = []
        ioc_list = []

        # 分析告警类型
        has_hidden_file = any("隐藏文件" in str(a.get("rule", {}).get("rule_name", "")) for a in all_alerts)
        has_sensitive_write = any("敏感" in str(a.get("rule", {}).get("rule_name", "")) for a in all_alerts)
        has_suspicious_process = any("可疑进程" in str(a.get("rule", {}).get("rule_name", "")) for a in all_alerts)
        has_network_anomaly = any("网络" in str(a.get("rule", {}).get("rule_name", "")) for a in all_alerts)
        has_escalation = any("提权" in str(a.get("rule", {}).get("rule_name", "")) for a in all_alerts)

        # 构建攻击阶段
        if has_hidden_file or has_suspicious_process:
            attack_stages.append({
                "stage": "初始访问",
                "description": "攻击者通过可疑进程或隐藏文件获取系统访问权限",
                "techniques": ["T1564.001", "T1059"],
                "evidence": [f"检测到 {len([a for a in all_alerts if '隐藏' in str(a.get('rule', {}).get('rule_name', ''))])} 条隐藏文件相关告警"]
            })
            key_findings.append(f"发现隐藏文件或可疑进程活动，可能是恶意载荷投递的迹象")

        if has_sensitive_write:
            attack_stages.append({
                "stage": "持久化",
                "description": "攻击者尝试修改敏感系统文件以建立持久化后门",
                "techniques": ["T1547", "T1574"],
                "evidence": [f"检测到 {len([a for a in all_alerts if '敏感' in str(a.get('rule', {}).get('rule_name', ''))])} 条敏感文件访问告警"]
            })
            key_findings.append("检测到对敏感系统目录/文件的异常写入行为")
            ioc_list.append({
                "type": "file",
                "value": "/etc/passwd",
                "description": "攻击者尝试访问敏感认证文件"
            })

        if has_escalation:
            attack_stages.append({
                "stage": "权限提升",
                "description": "攻击者尝试提升权限以获取更高系统访问能力",
                "techniques": ["T1068", "T1548"],
                "evidence": ["检测到权限提升相关行为模式"]
            })
            key_findings.append("发现权限提升尝试，可能导致系统完全沦陷")

        if has_network_anomaly:
            attack_stages.append({
                "stage": "命令与控制",
                "description": "检测到异常网络连接，可能是C2通信",
                "techniques": ["T1071", "T1095"],
                "evidence": [f"检测到 {len([a for a in all_alerts if '网络' in str(a.get('rule', {}).get('rule_name', ''))])} 条网络异常告警"]
            })
            key_findings.append("发现可疑网络连接，可能与外部C2服务器通信")
            ioc_list.append({
                "type": "ip",
                "value": "192.168.1.100",
                "description": "检测到与可疑IP的异常连接"
            })

        # 如果没有明确阶段，添加默认阶段
        if not attack_stages:
            attack_stages.append({
                "stage": "异常检测",
                "description": "系统检测到多项可疑行为模式",
                "techniques": [],
                "evidence": [f"共触发 {alert_count} 条告警规则"]
            })
            key_findings.append(f"系统共检测到 {alert_count} 条告警，涉及多个安全维度")

        # 生成攻击叙述
        narrative = self._generate_mock_narrative(attack_stages, alert_count, high_count)

        # 如果没有IOC，添加一些示例
        if not ioc_list:
            ioc_list.append({
                "type": "process",
                "value": "suspicious_process",
                "description": "检测到可疑进程行为"
            })

        return {
            "summary": summary,
            "threat_level": threat_level,
            "attack_stages": attack_stages,
            "attack_narrative": narrative,
            "key_findings": key_findings[:5],  # 最多5条
            "ioc_list": ioc_list[:10],  # 最多10条
            "recommendations": []
        }

    def _generate_mock_narrative(self, stages: List[Dict], total_count: int, high_count: int) -> str:
        """生成模拟的攻击叙述"""
        narrative_parts = []

        # 开头
        if high_count >= 5:
            narrative_parts.append("在本次安全监控周期内，系统检测到一系列高度可疑的活动，这些行为模式符合已知APT攻击特征。")
        elif high_count >= 2:
            narrative_parts.append(f"系统在安全监控中检测到 {high_count} 条高危告警，这些告警之间存在一定的时序关联性。")
        else:
            narrative_parts.append("系统检测到若干异常安全事件，虽然单独看每个事件可能不构成直接威胁，但综合分析后仍需关注。")

        # 阶段描述
        if len(stages) > 1:
            narrative_parts.append("\n\n攻击过程可划分为以下阶段：")
            for i, stage in enumerate(stages, 1):
                narrative_parts.append(f"\n{i}. **{stage['stage']}**：{stage['description']}")

        # 总结
        narrative_parts.append(f"\n\n总体来看，本次监控共触发 {total_count} 条告警规则，其中高危告警 {high_count} 条。")
        if high_count >= 5:
            narrative_parts.append("鉴于告警数量较多且涉及多个攻击阶段，建议立即采取应急响应措施。")
        else:
            narrative_parts.append("建议安全团队对相关事件进行进一步调查确认。")

        return "".join(narrative_parts)

    def _mock_analysis(self, alerts: List[Dict]) -> Dict[str, Any]:
        """模拟分析（当 LLM 不可用时）"""
        high_alerts = [a for a in alerts if a.get("rule", {}).get("severity") == "high"]

        return {
            "original_alerts_count": len(alerts),
            "filtered_alerts_count": len(alerts),
            "filtered_alerts": alerts[:100],
            "attack_story": self._generate_fallback_story(alerts, ""),
            "analysis_report": {
                "severity_summary": {"high": len(high_alerts), "medium": len(alerts) - len(high_alerts)},
                "total_filtered": len(alerts),
                "attack_types": ["文件异常", "进程异常", "网络异常"],
                "affected_assets": [],
                "timeline": []
            },
            "recommendations": [
                "LLM 服务未配置，建议配置 OpenAI API Key 以获得智能分析",
                "当前显示为规则引擎基础检测结果"
            ],
            "analyzed_at": datetime.now().isoformat() + "Z",
            "llm_available": False
        }


# 全局实例
_analyzer = None


def get_llm_analyzer() -> LLMAnalyzer:
    """获取 LLM 分析器单例"""
    global _analyzer
    if _analyzer is None:
        _analyzer = LLMAnalyzer()
    return _analyzer


if __name__ == "__main__":
    # 测试
    async def test():
        analyzer = LLMAnalyzer()
        print(f"LLM 可用: {analyzer.is_available()}")

        # 模拟告警数据
        mock_alerts = [
            {
                "event_id": "evt_001",
                "timestamp": "2025-03-20T10:30:00Z",
                "subject": {"type": "process", "id": "proc_9999", "name": ".hidden_malware"},
                "object": {"type": "file", "id": "file_001", "path": "/etc/passwd"},
                "action": "write",
                "rule": {"rule_id": "R001", "rule_name": "敏感目录写入", "severity": "high"},
                "message": "可疑进程写入敏感文件",
                "severity": "high"
            }
        ]

        result = await analyzer.analyze_alerts(mock_alerts, {}, [])
        print(json.dumps(result, ensure_ascii=False, indent=2))

    asyncio.run(test())
