# -*- coding: utf-8 -*-
"""
攻击链重建模块
使用聚类算法和 ATT&CK 映射重建攻击链
"""

import json
from typing import List, Dict, Any, Set
from collections import defaultdict
import numpy as np


class AttackChainBuilder:
    """攻击链重建器 - 将分散的告警聚合成攻击链"""

    def __init__(self):
        """初始化攻击链重建器"""

        # ATT&CK 技术映射
        self.attack_techniques = {
            # 初始访问
            "T1190": "Exploit Public-Facing Application",
            "T1195": "Supply Chain Compromise",
            "T1566": "Phishing",

            # 执行
            "T1059": "Command and Scripting Interpreter",
            "T1204": "User Execution",
            "T1203": "Exploitation for Client Execution",

            # 持久化
            "T1547": "Boot or Logon Autostart Execution",
            "T1053": "Scheduled Task/Job",
            "T1543": "Create or Modify System Process",

            # 权限提升
            "T1068": "Exploitation for Privilege Escalation",
            "T1548": "Abuse Elevation Control Mechanism",

            # 防御规避
            "T1027": "Obfuscated Files or Information",
            "T1055": "Process Injection",
            "T1014": "Rootkit",
            "T1070": "Indicator Removal",

            # 凭证访问
            "T1003": "OS Credential Dumping",
            "T1552": "Unsecured Credentials",

            # 发现
            "T1018": "Remote System Discovery",
            "T1046": "Network Service Scanning",
            "T1005": "Data from Local System",

            # 横向移动
            "T1021": "Remote Services",
            "T1570": "Lateral Tool Transfer",

            # 收集
            "T1005": "Data from Local System",
            "T1074": "Data Staged",

            # 渗漏
            "T1041": "Exfiltration Over C2 Channel",
            "T1567": "Exfiltration Over Web Service",

            # C2
            "T1071": "Application Layer Protocol",
            "T1095": "Non-Application Layer Protocol",

            # 影响
            "T1486": "Data Encrypted for Impact",
            "T1496": "Resource Hijacking",

            # 其他
            "T1105": "Ingress Tool Transfer",
            "T1505": "Server Software Component",
            "T1043": "Commonly Used Port",
            "T1110": "Brute Force",
            "T1078": "Valid Accounts",
            "T1012": "Query Registry",
            "T1222": "File and Directory Permissions Modification",
            "T1547": "Boot or Logon Autostart Execution",
            "T1557": "Adversary-in-the-Middle",
            "T1611": "Escape to Host"
        }

        # 规则到 ATT&CK 技术的映射
        self.rule_to_attack = {
            "R001": "T1222",  # 文件和目录权限修改
            "R002": "T1105",  # 工具传输
            "R003": "T1059",  # 命令行界面
            "R004": "T1005",  # 本地系统数据
            "R005": "T1070",  # 指示器移除
            "R006": "T1012",  # 查询注册表
            "R101": "T1204",  # 用户执行
            "R102": "T1055",  # 进程注入
            "R103": "T1547",  # 启动/登录自动执行
            "R104": "T1027",  # 混淆的文件或信息
            "R105": "T1014",  # Rootkit
            "R106": "T1059",  # 命令和脚本解释器
            "R201": "T1071",  # 应用层协议
            "R202": "T1071",  # 应用层协议
            "R203": "T1071",  # 应用层协议
            "R204": "T1043",  # 常用端口
            "R205": "T1048",  # Exfiltration Over C2 Channel
            "R302": "T1071",  # 应用层协议
            "R303": "T1041",  # 通过 C2 通道渗漏
            "R304": "T1547",  # 启动/登录自动执行
            "R305": "T1005",  # 本地系统数据
            "R401": "T1078",  # 有效账户
            "R402": "T1078",  # 有效账户
            "R403": "T1110",  # 暴力破解
        }

        # 聚类配置
        self.cluster_config = {
            "eps": 0.5,           # DBSCAN 邻域半径
            "min_samples": 2,     # 最小样本数
            "max_chains": 10      # 最大攻击链数
        }

    def build_attack_chains(self, graph: Dict, alerts: List[Dict],
                           threat_scores: Dict) -> Dict:
        """
        构建攻击链

        Args:
            graph: 图数据
            alerts: 规则检测告警
            threat_scores: 节点威胁评分

        Returns:
            Dict: 攻击链重建结果
        """
        print("开始重建攻击链...")

        # 1. 识别告警节点
        alert_nodes = self._identify_alert_nodes(alerts, threat_scores)

        if not alert_nodes:
            return {
                "attack_chains": [],
                "statistics": {
                    "total_chains": 0,
                    "total_nodes_in_chains": 0
                }
            }

        # 2. 提取告警节点特征
        alert_features = self._extract_alert_features(alert_nodes, graph, threat_scores)

        # 3. 对告警节点进行聚类
        clusters = self._cluster_alert_nodes(alert_nodes, alert_features)

        # 4. 为每个簇构建攻击链
        attack_chains = []
        for cluster_id, nodes in clusters.items():
            chain = self._build_chain_from_cluster(
                cluster_id, nodes, graph, alerts, threat_scores
            )
            if chain:
                attack_chains.append(chain)

        # 5. 生成统计信息
        result = {
            "attack_chains": attack_chains,
            "statistics": self._calculate_chain_statistics(attack_chains)
        }

        print(f"攻击链重建完成: {len(attack_chains)} 条攻击链")
        return result

    def _identify_alert_nodes(self, alerts: List[Dict],
                             threat_scores: Dict) -> Set[str]:
        """识别告警节点"""
        alert_nodes = set()

        # 从告警中提取节点
        for alert in alerts:
            subj_id = alert.get("subject", {}).get("id", "")
            obj_id = alert.get("object", {}).get("id", "")
            if subj_id:
                alert_nodes.add(subj_id)
            if obj_id:
                alert_nodes.add(obj_id)

        # 添加高威胁评分的节点
        for node_id, score in threat_scores.items():
            if score > 0.5:
                alert_nodes.add(node_id)

        return alert_nodes

    def _extract_alert_features(self, alert_nodes: Set[str],
                                graph: Dict, threat_scores: Dict) -> Dict:
        """提取告警节点特征"""
        features = {}
        nodes_dict = {n["id"]: n for n in graph.get("nodes", [])}

        for node_id in alert_nodes:
            node = nodes_dict.get(node_id, {})

            # 基础特征
            feature = {
                "id": node_id,
                "type": node.get("type", "unknown"),
                "name": node.get("name", ""),
                "threat_score": threat_scores.get(node_id, 0.0),
                "label": node.get("label", "unknown")
            }

            # 编码特征
            encoded = self._encode_node_features(node, graph)
            feature["encoded"] = encoded

            features[node_id] = feature

        return features

    def _encode_node_features(self, node: Dict, graph: Dict) -> np.ndarray:
        """
        编码节点特征
        包括结构特征和 ATT&CK 编码
        """
        # 基础特征
        base_features = [
            node.get("degree", 0),
            1.0 if node.get("type") == "process" else 0.0,
            1.0 if node.get("type") == "file" else 0.0,
            1.0 if node.get("type") == "socket" else 0.0,
            node.get("label") == "malicious"
        ]

        # ATT&CK 技术编码 (简化版)
        attack_vector = [0.0] * 10  # 选择10个常见技术
        # 这里可以根据实际触发的规则设置

        return np.array(base_features + attack_vector)

    def _cluster_alert_nodes(self, alert_nodes: Set[str],
                            alert_features: Dict) -> Dict[int, List[str]]:
        """
        对告警节点进行聚类
        使用简化的 DBSCAN 算法
        """
        if not alert_nodes:
            return {}

        # 准备特征矩阵
        node_ids = list(alert_nodes)
        X = np.array([alert_features[nid]["encoded"] for nid in node_ids])

        # 标准化
        X_mean = X.mean(axis=0)
        X_std = X.std(axis=0) + 1e-8
        X_normalized = (X - X_mean) / X_std

        # 简化的 DBSCAN 实现
        eps = self.cluster_config["eps"]
        min_samples = self.cluster_config["min_samples"]

        clusters = {}
        visited = set()
        cluster_id = 0

        for i, nid in enumerate(node_ids):
            if nid in visited:
                continue

            # 找到邻域内的点
            neighbors = []
            for j, other_nid in enumerate(node_ids):
                if i != j:
                    dist = np.linalg.norm(X_normalized[i] - X_normalized[j])
                    if dist <= eps:
                        neighbors.append(other_nid)

            # 如果邻域内点数足够，创建新簇
            if len(neighbors) >= min_samples - 1:
                # 扩展簇
                cluster_nodes = [nid] + neighbors
                for cn in cluster_nodes:
                    visited.add(cn)

                clusters[cluster_id] = cluster_nodes
                cluster_id += 1
            else:
                # 标记为噪声点（单独成簇）
                visited.add(nid)
                clusters[cluster_id] = [nid]
                cluster_id += 1

        return clusters

    def _build_chain_from_cluster(self, cluster_id: int, nodes: List[str],
                                  graph: Dict, alerts: List[Dict],
                                  threat_scores: Dict) -> Dict:
        """
        从节点簇构建攻击链
        """
        # 获取节点信息
        nodes_dict = {n["id"]: n for n in graph.get("nodes", [])}
        edges_dict = {e["id"]: e for e in graph.get("edges", [])}

        # 筛选相关告警
        related_alerts = []
        for alert in alerts:
            subj_id = alert.get("subject", {}).get("id", "")
            obj_id = alert.get("object", {}).get("id", "")
            if subj_id in nodes or obj_id in nodes:
                related_alerts.append(alert)

        # 提取攻击技术
        techniques = self._extract_attack_techniques(related_alerts)

        # 构建攻击路径
        attack_path = self._build_attack_path(nodes, graph)

        # 计算威胁评分
        chain_threat_score = self._calculate_chain_threat_score(
            nodes, threat_scores, related_alerts
        )

        # 识别攻击类型
        attack_type = self._identify_attack_type(techniques, nodes_dict, nodes)

        return {
            "chain_id": f"chain_{cluster_id}",
            "attack_type": attack_type,
            "nodes": nodes,
            "node_count": len(nodes),
            "attack_path": attack_path,
            "attack_techniques": techniques,
            "related_alerts": [a.get("event_id", "") for a in related_alerts],
            "threat_score": chain_threat_score,
            "description": self._generate_chain_description(attack_type, techniques)
        }

    def _extract_attack_techniques(self, alerts: List[Dict]) -> List[str]:
        """从告警中提取攻击技术"""
        techniques = set()

        for alert in alerts:
            rule_id = alert.get("rule", {}).get("rule_id", "")
            if rule_id in self.rule_to_attack:
                techniques.add(self.rule_to_attack[rule_id])

            # 同时使用告警中的技术字段
            technique = alert.get("rule", {}).get("technique", "")
            if technique:
                techniques.add(technique)

        return list(techniques)

    def _build_attack_path(self, nodes: List[str], graph: Dict) -> List[Dict]:
        """构建攻击路径"""
        nodes_dict = {n["id"]: n for n in graph.get("nodes", [])}
        edges = graph.get("edges", [])

        # 找出节点之间的边
        path_edges = []
        for edge in edges:
            if edge["source"] in nodes and edge["target"] in nodes:
                path_edges.append({
                    "from": edge["source"],
                    "to": edge["target"],
                    "action": edge["action"],
                    "timestamp": edge.get("timestamps", [""])[0] if edge.get("timestamps") else ""
                })

        # 按时间排序
        path_edges.sort(key=lambda x: x["timestamp"])

        return path_edges

    def _calculate_chain_threat_score(self, nodes: List[str],
                                     threat_scores: Dict,
                                     alerts: List[Dict]) -> float:
        """计算攻击链威胁评分"""
        if not nodes:
            return 0.0

        # 节点威胁评分平均
        node_scores = [threat_scores.get(n, 0.0) for n in nodes]
        avg_node_score = sum(node_scores) / len(node_scores)

        # 告警数量因子
        alert_count = len(alerts)
        alert_factor = min(alert_count / 10.0, 0.3)

        # 链长度因子
        length_factor = min(len(nodes) / 20.0, 0.2)

        total_score = avg_node_score * 0.5 + alert_factor + length_factor

        return round(min(total_score, 1.0), 3)

    def _identify_attack_type(self, techniques: List[str],
                             nodes_dict: Dict, nodes: List[str]) -> str:
        """识别攻击类型"""
        # 根据 ATT&CK 技术识别攻击类型
        if "T1190" in techniques or "T1195" in techniques:
            return "初始访问"
        elif "T1059" in techniques and "T1055" in techniques:
            return "进程注入"
        elif "T1003" in techniques:
            return "凭证窃取"
        elif "T1041" in techniques:
            return "数据渗漏"
        elif "T1071" in techniques and "T1059" in techniques:
            return "后门通信"
        elif "T1547" in techniques:
            return "持久化"
        elif "T1068" in techniques:
            return "权限提升"
        elif "T1611" in techniques:
            return "容器逃逸"
        elif "T1486" in techniques:
            return "勒索软件"
        elif "T1496" in techniques:
            return "挖矿程序"
        else:
            # 根据节点类型推断
            node_types = [nodes_dict.get(n, {}).get("type", "") for n in nodes]
            if "socket" in node_types and "file" in node_types:
                return "数据窃取"
            elif "socket" in node_types:
                return "网络通信"
            else:
                return "未知攻击类型"

    def _generate_chain_description(self, attack_type: str,
                                    techniques: List[str]) -> str:
        """生成攻击链描述"""
        tech_names = [self.attack_techniques.get(t, t) for t in techniques]
        tech_desc = ", ".join(tech_names[:3])  # 最多显示3个

        return f"检测到 {attack_type} 攻击链。涉及技术: {tech_desc}"

    def _calculate_chain_statistics(self, chains: List[Dict]) -> Dict:
        """计算攻击链统计信息"""
        total_nodes = sum(c["node_count"] for c in chains)

        # 统计攻击类型
        attack_types = defaultdict(int)
        for chain in chains:
            attack_types[chain["attack_type"]] += 1

        # 统计攻击技术
        all_techniques = []
        for chain in chains:
            all_techniques.extend(chain["attack_techniques"])

        technique_counter = defaultdict(int)
        for tech in all_techniques:
            technique_counter[tech] += 1

        return {
            "total_chains": len(chains),
            "total_nodes_in_chains": total_nodes,
            "by_attack_type": dict(attack_types),
            "top_techniques": sorted(technique_counter.items(),
                                    key=lambda x: x[1], reverse=True)[:5],
            "avg_threat_score": sum(c["threat_score"] for c in chains) / len(chains) if chains else 0.0
        }


if __name__ == "__main__":
    # 测试攻击链重建
    from modules.data_generator import DataGenerator
    from modules.event_extractor import EventExtractor
    from modules.graph_builder import GraphBuilder
    from modules.rule_engine import RuleEngine
    from modules.threat_detector import ThreatDetector

    print("生成测试数据...")
    generator = DataGenerator()
    log_data = generator.generate(total_events=1000)

    print("提取事件...")
    extractor = EventExtractor()
    events = extractor.extract_from_logs(log_data)

    print("构建图...")
    builder = GraphBuilder()
    graph = builder.build_graph(events)

    print("规则检测...")
    engine = RuleEngine()
    rule_result = engine.evaluate_events(events)

    print("威胁检测...")
    detector = ThreatDetector()
    threat_result = detector.detect(graph, rule_result.get("alerts", []))

    print("重建攻击链...")
    chain_builder = AttackChainBuilder()
    chains_result = chain_builder.build_attack_chains(
        graph,
        rule_result.get("alerts", []),
        threat_result["threat_scores"]
    )

    print(f"攻击链统计: {chains_result['statistics']}")
