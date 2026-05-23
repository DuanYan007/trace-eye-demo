# -*- coding: utf-8 -*-
"""
大模型告警分析模块
基于 OpenAI GPT 进行告警分析、降噪和攻击故事生成
支持模拟模式（不调用真实 API）
"""

import os
import json
import asyncio
import hashlib
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime
from collections import Counter
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
        default_model = "deepseek-v4" if self.provider == "deepseek" else "gpt-4o-mini"
        self.model = model or os.environ.get("LLM_MODEL") or default_model

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
            "max_tokens": int(os.environ.get("LLM_MAX_TOKENS", "5000")),
            "temperature": float(os.environ.get("LLM_TEMPERATURE", "0.65")),
            "top_p": float(os.environ.get("LLM_TOP_P", "0.92")),
            "enable_streaming": True,
            "analysis_timeout": 180  # 超时时间(秒)
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

    async def test_connection(self) -> Dict[str, Any]:
        """Test the configured chat-completions endpoint with a tiny request."""
        if not self.api_key:
            return {
                "success": False,
                "message": "未配置 API Key，请先设置 DEEPSEEK_API_KEY 或 OPENAI_API_KEY。"
            }
        if not HAS_OPENAI:
            return {
                "success": False,
                "message": "未安装 openai SDK，请先安装 requirements.txt 中的依赖。"
            }
        if not self.client:
            return {
                "success": False,
                "message": "LLM 客户端初始化失败，请检查 API Base 与网络连接。"
            }

        try:
            await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a connection test responder."},
                    {"role": "user", "content": "Reply with OK."}
                ],
                max_tokens=8,
                temperature=0
            )
            return {
                "success": True,
                "message": f"连接测试通过，模型 {self.model} 可访问。"
            }
        except Exception as exc:
            return {
                "success": False,
                "message": f"连接测试失败: {exc}"
            }

    async def analyze_alerts(
        self,
        alerts: List[Dict],
        graph: Dict,
        events: List[Dict],
        progress_callback: Optional[Callable] = None,
        detection_context: Optional[Dict[str, Any]] = None
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
        priority_alerts = [
            a for a in deduped_alerts
            if a.get("severity") in ["critical", "high", "medium"]
        ] or deduped_alerts[:20]

        # 3. 生成攻击故事
        attack_story = await self._generate_attack_story(
            priority_alerts[:30],  # 限制输入数量
            graph,
            events,
            detection_context or {},
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
            "detection_context": detection_context or {},
            "analyzed_at": datetime.now().isoformat() + "Z",
            "llm_mode": "real"
        })

    async def _deduplicate_alerts(self, alerts: List[Dict], graph: Dict) -> List[Dict]:
        """告警降噪：去除重复和低质量告警"""
        # 按主体、客体、动作和规则去重，并优先保留高风险告警。
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
        sorted_alerts = sorted(
            alerts or [],
            key=lambda alert: severity_rank.get(alert.get("rule", {}).get("severity", alert.get("severity", "unknown")), 0),
            reverse=True
        )
        seen = set()
        deduped = []

        for alert in sorted_alerts:
            subject_id = alert.get("subject", {}).get("id", "")
            object_id = alert.get("object", {}).get("id", "")
            action = alert.get("action", "")
            rule_id = alert.get("rule", {}).get("rule_id", alert.get("rule", {}).get("rule_name", ""))
            key = f"{subject_id}:{object_id}:{action}:{rule_id}"

            severity = alert.get("rule", {}).get("severity", alert.get("severity", "low"))
            if key not in seen:
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
            if len(deduped) >= 120:
                break

        return deduped

    async def _generate_attack_story(
        self,
        alerts: List[Dict],
        graph: Dict,
        events: List[Dict],
        detection_context: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """生成攻击故事"""
        if not alerts:
            return self._generate_fallback_story([], "没有可用于 LLM 分析的优先级告警。")

        if progress_callback:
            await progress_callback(50, "生成攻击叙述...")

        # 构建上下文信息
        context = self._build_context(alerts, graph, events, detection_context or {})

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

    def _build_context(self, alerts: List[Dict], graph: Dict, events: List[Dict], detection_context: Dict[str, Any] = None) -> str:
        """构建 LLM 上下文"""
        detection_context = detection_context or {}
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
        priority_alerts = sorted(
            alerts or [],
            key=lambda alert: severity_rank.get(alert.get("severity", "unknown"), 0),
            reverse=True
        )[:25]
        severity_counts = Counter(alert.get("severity", "unknown") for alert in alerts or [])
        graph_stats = graph.get("statistics", {}) if isinstance(graph, dict) else {}
        threat_summary = detection_context.get("threat_summary") or {}
        relation_stats = detection_context.get("relation_statistics") or {}
        chain_stats = detection_context.get("chain_statistics") or {}
        attack_chains = detection_context.get("attack_chains") or []
        classified_nodes = detection_context.get("classified_nodes") or {}
        threat_scores = detection_context.get("threat_scores") or {}
        top_threat_scores = detection_context.get("top_threat_scores") or []
        suspicious_relations = detection_context.get("suspicious_relations") or []
        focus_modes = [
            "攻击路径优先：先判断攻击者如何串联事件，再回推薄弱点",
            "资产影响优先：先识别受影响资产，再判断攻击阶段",
            "规则可信度优先：先区分强证据与弱证据，再给出处置顺序",
            "修复闭环优先：先定义可验证的修复目标，再组织诊断结论"
        ]
        context_fingerprint = hashlib.sha1(
            json.dumps({
                "severity": dict(severity_counts),
                "threat": threat_summary,
                "relations": relation_stats,
                "chains": chain_stats,
                "alert_sample": [
                    {
                        "rule": alert.get("rule", {}).get("rule_id") or alert.get("rule", {}).get("rule_name"),
                        "severity": alert.get("severity"),
                        "subject": alert.get("subject", {}).get("name"),
                        "object": alert.get("object", {}).get("name") or alert.get("object", {}).get("path") or alert.get("object", {}).get("ip")
                    }
                    for alert in priority_alerts[:12]
                ]
            }, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()[:10]
        focus_index = int(context_fingerprint[:2], 16) % len(focus_modes)
        focus_hint = focus_modes[focus_index]
        top_threat_nodes = top_threat_scores[:20] if top_threat_scores else (
            sorted(
                threat_scores.items(),
                key=lambda item: item[1],
                reverse=True
            )[:20] if isinstance(threat_scores, dict) else []
        )

        context_parts = [
            "【系统检测摘要】",
            f"- 降噪后告警数量: {len(alerts)}",
            f"- 告警严重度分布: {dict(severity_counts)}",
            f"- 关系图规模: 节点 {graph_stats.get('node_count', len(graph.get('nodes', [])) if isinstance(graph, dict) else 0)}, 边 {graph_stats.get('edge_count', len(graph.get('edges', [])) if isinstance(graph, dict) else 0)}",
            f"- 威胁检测摘要: {json.dumps(threat_summary, ensure_ascii=False)}",
            f"- 关系挖掘统计: {json.dumps(relation_stats, ensure_ascii=False)}",
            f"- 攻击链统计: {json.dumps(chain_stats, ensure_ascii=False)}",
            f"- 本次分析指纹: {context_fingerprint}",
            f"- 推荐分析视角: {focus_hint}",
            "",
            "【威胁节点摘要】",
            f"- 分级节点数量: {json.dumps({k: len(v or []) for k, v in classified_nodes.items()}, ensure_ascii=False)}",
            f"- Top 威胁评分节点: {json.dumps(top_threat_nodes, ensure_ascii=False)}",
            "",
            "【可疑关系样本】",
            json.dumps(suspicious_relations[:12], ensure_ascii=False),
            "",
            "【优先级告警样本】"
        ]

        for i, alert in enumerate(priority_alerts, 1):
            rule_name = alert.get("rule", {}).get("rule_name", "未知规则")
            subject = alert.get("subject", {}).get("name", "未知进程")
            obj = alert.get("object", {})
            obj_info = obj.get("name", "") or obj.get("path", "") or obj.get("ip", "")
            timestamp = alert.get("timestamp", "")[:16]
            severity = alert.get("severity", "unknown")
            message = alert.get("message", "")

            context_parts.append(
                f"{i}. [{severity}] [{timestamp}] {rule_name}\n"
                f"   主体: {subject}\n"
                f"   客体: {obj_info}\n"
                f"   说明: {message}\n"
            )

        if attack_chains:
            context_parts.extend(["", "【攻击链重建结果】"])
            for index, chain in enumerate(attack_chains[:5], 1):
                context_parts.append(
                    f"{index}. {chain.get('title') or chain.get('description') or chain.get('attack_type') or '未命名攻击链'}\n"
                    f"   阶段: {chain.get('primary_tactic') or chain.get('stage') or '-'}\n"
                    f"   节点数: {chain.get('node_count', len(chain.get('nodes', [])) if isinstance(chain.get('nodes'), list) else '-')}\n"
                    f"   告警数: {chain.get('alert_count', len(chain.get('alerts', [])) if isinstance(chain.get('alerts'), list) else '-')}"
                )

        return "\n".join(context_parts)

    def _get_story_prompt(self, context: str) -> str:
        """获取攻击故事生成的提示词"""
        return f"""你是 Trace-Eye APT 检测系统中的资深安全分析师。请基于给定检测结果生成结构化 AI 分析报告。

重要约束：
1. 必须使用中文。
2. 只能基于输入证据分析，不要编造不存在的 IP、文件、账号或漏洞。
3. 输出必须是严格 JSON，不要 Markdown 代码块，不要 HTML，不要解释性前后缀。
4. 你需要像真实分析师一样自主研判，不要套用固定模板；每次应根据输入的威胁节点、可疑关系、攻击链和告警分布选择分析重点。
5. 结论要具体，避免“建议进一步分析”这类空话单独成段。任何判断都必须能回指到输入中的规则、节点、关系、攻击链或统计。
6. `diagnosis_markdown` 说明系统存在什么问题；`remediation_markdown` 说明应当如何修复系统。
7. Markdown 标题由你自主命名，不要固定使用“总体判断/告警严重度/IOC 指标/后续加固”这套模板。标题应体现本次数据特征。
8. 如果证据不足，请明确写出“不足以证明”的边界，而不是编造攻击事实。

自主分析要求：
- 先识别本次数据最值得关注的 2-4 个异常主题，而不是平均覆盖所有字段。
- 对每个主题给出“证据 -> 推断 -> 风险 -> 修复验证”的链路。
- 报告应出现至少 3 个来自输入的具体证据值，例如规则名、节点名、路径、进程、IP、攻击链阶段或统计数量。
- 修复建议要按优先级组织，允许根据威胁上下文自行设计处置顺序。
- 不要为了格式整齐牺牲判断力；如果某类数据不重要，可以少写或不写。

## 检测上下文
{context}

## 输出 JSON Schema

{{
  "summary": "2-3 句话概括整体威胁状况，必须引用关键统计或证据",
  "threat_level": "评估威胁等级 (critical/high/medium/low)",
  "attack_stages": [
    {{
      "stage": "阶段名称，例如初始访问、执行、持久化、命令与控制、横向移动、影响",
      "description": "该阶段发生了什么，受影响对象是什么",
      "techniques": ["可映射的 ATT&CK 技术编号或技术名；不确定就写空数组"],
      "evidence": ["从输入中抽取的主体、客体、规则、攻击链或统计证据"]
    }}
  ],
  "attack_narrative": "用连贯叙述描述攻击过程，既能被管理者理解，也能让分析师定位证据",
  "key_findings": [
    "具体问题1：说明问题、影响和证据",
    "具体问题2：说明问题、影响和证据"
  ],
  "ioc_list": [
    {{"type": "ip/file/process/domain/account", "value": "输入中真实出现的指标", "description": "为什么可疑"}}
  ],
  "recommendations": [
    "可执行的紧急处置建议",
    "可验证的修复建议"
  ],
  "diagnosis_markdown": "# 请自行命名的系统问题报告标题\\n\\n## 基于本次证据自行组织的小节...",
  "remediation_markdown": "# 请自行命名的修复建议标题\\n\\n## 按本次攻击面自行组织的小节..."
}}
"""

    async def _call_llm(self, prompt: str) -> str:
        """调用 LLM API"""
        request = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "你是资深 APT 威胁狩猎与应急响应专家。只输出严格 JSON，中文回答，拒绝编造证据。"},
                {"role": "user", "content": prompt}
            ],
            max_tokens=self.config["max_tokens"],
            temperature=self.config["temperature"],
            top_p=self.config["top_p"],
            timeout=self.config["analysis_timeout"]
        )
        response = await asyncio.wait_for(request, timeout=self.config["analysis_timeout"] + 10)
        return response.choices[0].message.content

    async def revise_report(self, current_report: Dict[str, Any], expert_message: str) -> Dict[str, Any]:
        """Revise the AI report with expert guidance."""
        diagnosis = current_report.get("diagnosis_markdown", "")
        remediation = current_report.get("remediation_markdown", "")
        expert_message = (expert_message or "").strip()

        if self.use_mock:
            note = expert_message or "专家要求对报告进行二次复核与智能修订。"
            return {
                "diagnosis_markdown": "\n".join([
                    diagnosis,
                    "",
                    "## 🧑‍💼 专家复核补充",
                    f"- 专家意见: {note}",
                    "- LLM 已根据专家意见重新强调证据链、影响范围和需要复核的关键资产。"
                ]).strip(),
                "remediation_markdown": "\n".join([
                    remediation,
                    "",
                    "## 🤖 LLM 智能修订",
                    f"- 修订依据: {note}",
                    "- 建议先由专家确认高危主机、关键 IOC 和业务影响，再按优先级执行隔离、封禁、补丁与二次验证。",
                    "- 修复完成后保留专家复核记录，并将确认后的检测逻辑沉淀为规则或响应剧本。"
                ]).strip(),
                "review_note": f"演示模式智能修订：{note}",
                "revised_at": datetime.now().isoformat() + "Z",
                "llm_mode": "mock"
            }

        prompt = f"""你是网络安全应急响应专家。请根据专家意见修订 Trace-Eye 的 AI 分析报告。

要求：
1. 保持 Markdown 格式。
2. 诊断报告说明系统存在什么问题、证据和影响。
3. 修复建议说明如何修复、验证和持续监控。
4. 不要删除专家明确要求保留的信息。
5. 仅返回 JSON，不要输出额外解释。

JSON 格式：
{{
  "diagnosis_markdown": "修订后的诊断报告 Markdown",
  "remediation_markdown": "修订后的修复建议 Markdown",
  "review_note": "一句话说明本次根据专家意见做了哪些调整"
}}

## 专家意见
{expert_message}

## 当前诊断报告
{diagnosis}

## 当前修复建议
{remediation}
"""
        response = await self._call_llm(prompt)
        parsed = self._parse_json_response(response)
        return {
            "diagnosis_markdown": parsed.get("diagnosis_markdown", diagnosis),
            "remediation_markdown": parsed.get("remediation_markdown", remediation),
            "review_note": parsed.get("review_note", expert_message or "LLM 已根据专家意见完成智能修订。"),
            "revised_at": datetime.now().isoformat() + "Z",
            "llm_mode": "real"
        }

    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """Parse a JSON object from a raw LLM response."""
        try:
            text = (response or "").strip()
            if text.startswith("```"):
                text = text.split("```", 1)[1]
                if text.startswith("json"):
                    text = text[4:]
                text = text.strip()
            if text.endswith("```"):
                text = text.rsplit("```", 1)[0].strip()
            if not text.startswith("{"):
                start = text.find("{")
                end = text.rfind("}")
                if start >= 0 and end > start:
                    text = text[start:end + 1]
            return json.loads(text)
        except Exception:
            return {}

    def _parse_story_response(self, response: str, alerts: List[Dict]) -> Dict:
        """解析 LLM 响应"""
        parsed = self._parse_json_response(response)
        if parsed:
            fallback = self._generate_fallback_story(alerts, response)
            for key, value in fallback.items():
                parsed.setdefault(key, value)
            return parsed
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

        generated_diagnosis = story.get("diagnosis_markdown") or result.get("diagnosis_markdown")
        generated_remediation = story.get("remediation_markdown") or result.get("remediation_markdown")

        result["diagnosis_markdown"] = generated_diagnosis or "\n".join([
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

        result["remediation_markdown"] = generated_remediation or "\n".join([
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
                "LLM 服务未配置，建议配置 DeepSeek API Key 以获得智能分析",
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
