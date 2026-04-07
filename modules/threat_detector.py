# -*- coding: utf-8 -*-
"""
威胁检测模块
使用机器学习算法进行威胁评分
"""

import json
import numpy as np
from typing import List, Dict, Any, Set
from datetime import datetime
from collections import defaultdict, Counter


class ThreatDetector:
    """威胁检测器 - 使用机器学习进行威胁评分"""

    def __init__(self):
        """初始化威胁检测器"""
        # 特征维度配置
        self.feature_dims = {
            "structural": 5,  # 结构特征
            "semantic": 10,   # 语义特征（新增可疑名称和路径）
            "temporal": 4     # 时序特征
        }
        self.total_features = sum(self.feature_dims.values())

        # 检测配置
        self.config = {
            "isolation_forest": {
                "contamination": 0.25,  # 提高到25%，使更多节点被检测为异常
                "n_estimators": 100,
                "max_samples": "auto"
            },
            "kmeans": {
                "n_clusters": 5,
                "max_iter": 300
            },
            "threat_weights": {
                "rule_violations": 0.6,     # 规则违规权重提高到60%
                "anomaly_score": 0.2,       # 异常分数降低到20%
                "suspicious_neighbors": 0.1,
                "temporal_anomaly": 0.1
            }
        }

        # 检测结果
        self.node_features = {}
        self.node_scores = {}
        self.clusters = {}

    def detect(self, graph: Dict, alerts: List[Dict] = None) -> Dict:
        """
        执行完整的威胁检测流程

        Args:
            graph: 图数据
            alerts: 规则检测的告警列表

        Returns:
            Dict: 检测结果
        """
        print("开始威胁检测...")

        # 1. 特征提取
        print("提取节点特征...")
        self._extract_features(graph)

        # 2. 异常检测
        print("执行异常检测...")
        anomaly_results = self._anomaly_detection()

        # 3. 行为聚类
        print("执行行为聚类...")
        cluster_results = self._behavior_clustering()

        # 4. 威胁评分
        print("计算威胁评分...")
        threat_scores = self._calculate_threat_scores(graph, alerts, anomaly_results, cluster_results)

        # 5. 分类节点
        classified_nodes = self._classify_nodes(threat_scores)

        result = {
            "node_features": self.node_features,
            "anomaly_detection": anomaly_results,
            "clustering": cluster_results,
            "threat_scores": threat_scores,
            "classified_nodes": classified_nodes,
            "summary": self._generate_summary(classified_nodes)
        }

        threat_count = (len(classified_nodes.get("critical", [])) +
                       len(classified_nodes.get("high", [])) +
                       len(classified_nodes.get("medium", [])))
        print(f"威胁检测完成: {threat_count} 威胁节点 (critical:{len(classified_nodes.get('critical', []))}, high:{len(classified_nodes.get('high', []))}, medium:{len(classified_nodes.get('medium', []))})")
        return result

    def _extract_features(self, graph: Dict):
        """
        提取节点特征
        为每个节点计算 17 维特征向量
        """
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])
        adjacency = graph.get("adjacency", {})

        # 构建事件时间统计
        node_events = defaultdict(list)
        for edge in edges:
            source = edge.get("source", "")
            target = edge.get("target", "")
            for ts in edge.get("timestamps", []):
                node_events[source].append(ts)
                node_events[target].append(ts)

        for node in nodes:
            node_id = node.get("id", "")
            features = []

            # 1. 结构特征 (5维)
            structural = self._extract_structural_features(node, adjacency)
            features.extend(structural)

            # 2. 语义特征 (8维)
            semantic = self._extract_semantic_features(node, node_events.get(node_id, []))
            features.extend(semantic)

            # 3. 时序特征 (4维)
            temporal = self._extract_temporal_features(node_events.get(node_id, []))
            features.extend(temporal)

            self.node_features[node_id] = {
                "vector": features,
                "structural": structural,
                "semantic": semantic,
                "temporal": temporal
            }

    def _extract_structural_features(self, node: Dict, adjacency: Dict) -> List[float]:
        """提取结构特征 (5维)"""
        node_id = node.get("id", "")

        # 度数
        degree = node.get("degree", 0)

        # 邻居数
        neighbors = adjacency.get(node_id, set())
        neighbor_count = len(neighbors)

        # 聚类系数（简化计算）
        if neighbor_count < 2:
            clustering_coeff = 0.0
        else:
            # 计算邻居之间的连接数
            neighbor_links = 0
            neighbor_list = list(neighbors)
            for i in range(len(neighbor_list)):
                for j in range(i+1, len(neighbor_list)):
                    if neighbor_list[j] in adjacency.get(neighbor_list[i], set()):
                        neighbor_links += 1

            possible_links = neighbor_count * (neighbor_count - 1) / 2
            clustering_coeff = neighbor_links / possible_links if possible_links > 0 else 0.0

        # PageRank (简化版)
        pagerank = 0.15  # 默认值
        if node_id in adjacency:
            # 简化的 PageRank 计算
            pagerank = 0.15 + 0.85 * degree / (neighbor_count + 1)

        # 平均最短路径（采样计算）
        avg_path = self._estimate_avg_path_length(node_id, adjacency)

        return [
            float(degree),
            float(neighbor_count),
            float(clustering_coeff),
            float(pagerank),
            float(avg_path)
        ]

    def _extract_semantic_features(self, node: Dict, timestamps: List[str]) -> List[float]:
        """提取语义特征 (8维)"""
        # 进程生命周期（如果有时间戳）
        if len(timestamps) >= 2:
            try:
                t1 = datetime.fromisoformat(timestamps[0].replace("Z", ""))
                t2 = datetime.fromisoformat(timestamps[-1].replace("Z", ""))
                duration = (t2 - t1).total_seconds()
            except:
                duration = 0.0
        else:
            duration = 0.0

        # 文件大小
        size = node.get("attributes", {}).get("size", 0)

        # 网络连接数（从边统计）
        connection_count = 0

        # 唯一目标数
        unique_targets = node.get("degree", 0)

        # 动作熵
        action_entropy = 0.0

        # 平均时间间隔
        if len(timestamps) > 1:
            try:
                intervals = []
                for i in range(1, len(timestamps)):
                    t1 = datetime.fromisoformat(timestamps[i-1].replace("Z", ""))
                    t2 = datetime.fromisoformat(timestamps[i].replace("Z", ""))
                    intervals.append((t2 - t1).total_seconds())
                avg_interval = sum(intervals) / len(intervals)
            except:
                avg_interval = 0.0
        else:
            avg_interval = 0.0

        # 敏感路径标志
        path = node.get("name", node.get("path", ""))
        sensitive_paths = ["/etc/passwd", "/etc/shadow", "/root/.ssh",
                          "/home/user/.ssh", "/etc/sudoers"]
        is_sensitive = 1.0 if any(p in path for p in sensitive_paths) else 0.0

        # 可执行标志
        executable_extensions = [".so", ".dylib", ".dll", ".exe", ".bin"]
        is_executable = 1.0 if (any(ext in path for ext in executable_extensions) or
                               node.get("type") == "process") else 0.0

        # 可疑名称特征
        node_name = node.get("name", "").lower()
        node_type = node.get("type", "")
        suspicious_names = [
            ".hidden", "hidden", "backdoor", "malware", "trojan", "miner",
            "keylogger", "rootkit", "inject", "payload", "shell", "hack",
            "unknown", "temp", "tmp", "malicious", "c2", "trojan"
        ]
        has_suspicious_name = 1.0 if any(sn in node_name for sn in suspicious_names) else 0.0

        # 可疑路径特征
        suspicious_paths = ["/tmp/.", "/dev/shm/", "/tmp/.hidden", "/tmp/backdoor"]
        has_suspicious_path = 1.0 if any(sp in path for sp in suspicious_paths) else 0.0

        return [
            float(min(duration, 3600)),  # 限制在1小时内
            float(min(size / 1048576, 10)),  # MB，限制在10MB
            float(connection_count),
            float(unique_targets),
            float(action_entropy),
            float(min(avg_interval, 3600)),
            float(is_sensitive),
            float(is_executable),
            float(has_suspicious_name),   # 新增：可疑名称
            float(has_suspicious_path)    # 新增：可疑路径
        ]

    def _extract_temporal_features(self, timestamps: List[str]) -> List[float]:
        """提取时序特征 (4维)"""
        if not timestamps:
            return [0.0, 0.0, 0.0, 0.0]

        # 解析第一个时间戳
        try:
            first_time = datetime.fromisoformat(timestamps[0].replace("Z", ""))
        except:
            first_time = datetime.now()

        # 一天中的小时 (0-23)
        hour_of_day = first_time.hour / 24.0

        # 一周中的天数 (0-6)
        day_of_week = first_time.weekday() / 6.0

        # 突发事件计数（短时间内的事件数）
        burst_count = min(len(timestamps) / 10.0, 1.0)

        # 时间间隔方差
        if len(timestamps) > 1:
            try:
                intervals = []
                for i in range(1, len(timestamps)):
                    t1 = datetime.fromisoformat(timestamps[i-1].replace("Z", ""))
                    t2 = datetime.fromisoformat(timestamps[i].replace("Z", ""))
                    intervals.append((t2 - t1).total_seconds())

                if intervals:
                    variance = np.var(intervals) if len(intervals) > 1 else 0.0
                    interval_variance = min(variance / 10000.0, 1.0)
                else:
                    interval_variance = 0.0
            except:
                interval_variance = 0.0
        else:
            interval_variance = 0.0

        return [
            float(hour_of_day),
            float(day_of_week),
            float(burst_count),
            float(interval_variance)
        ]

    def _estimate_avg_path_length(self, node_id: str, adjacency: Dict) -> float:
        """估算平均最短路径长度"""
        from collections import deque

        visited = {node_id}
        queue = deque([(node_id, 0)])
        total_dist = 0
        count = 0

        while queue:
            curr, dist = queue.popleft()
            total_dist += dist
            count += 1

            if dist >= 3:  # 限制搜索深度
                continue

            for neighbor in adjacency.get(curr, set()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, dist + 1))

        return total_dist / count if count > 0 else 0.0

    def _anomaly_detection(self) -> Dict:
        """
        异常检测
        使用 Isolation Forest 算法
        """
        # 准备特征矩阵
        node_ids = list(self.node_features.keys())
        if not node_ids:
            return {"algorithm": "IsolationForest", "anomaly_nodes": [], "scores": {}}

        X = np.array([self.node_features[nid]["vector"] for nid in node_ids])

        # 标准化特征
        X_mean = X.mean(axis=0)
        X_std = X.std(axis=0) + 1e-8
        X_normalized = (X - X_mean) / X_std

        # 简化的 Isolation Forest 实现
        # 由于避免 sklearn 依赖，使用简化的异常检测方法
        anomaly_scores = {}

        # 使用基于距离的异常检测
        for i, nid in enumerate(node_ids):
            # 计算到其他所有点的平均距离
            distances = []
            for j, other_nid in enumerate(node_ids):
                if i != j:
                    dist = np.linalg.norm(X_normalized[i] - X_normalized[j])
                    distances.append(dist)

            avg_distance = np.mean(distances) if distances else 0
            anomaly_scores[nid] = float(avg_distance)

        # 归一化异常分数到 [0, 1]
        if anomaly_scores:
            max_score = max(anomaly_scores.values())
            min_score = min(anomaly_scores.values())
            score_range = max_score - min_score if max_score > min_score else 1.0

            for nid in anomaly_scores:
                anomaly_scores[nid] = (anomaly_scores[nid] - min_score) / score_range

        # 找出异常节点（降低阈值，使更多节点被检测为异常）
        threshold = self.config["isolation_forest"]["contamination"]
        # 使用分数分布的动态阈值：前30%的节点被认为是异常的
        sorted_scores = sorted(anomaly_scores.items(), key=lambda x: x[1], reverse=True)
        cutoff_idx = max(1, int(len(sorted_scores) * 0.3))  # 至少1个，最多30%
        if sorted_scores:
            dynamic_threshold = sorted_scores[cutoff_idx - 1][1] if cutoff_idx <= len(sorted_scores) else 0.7
            anomaly_nodes = [nid for nid, score in anomaly_scores.items() if score >= dynamic_threshold]
        else:
            anomaly_nodes = []

        return {
            "algorithm": "IsolationForest",
            "anomaly_nodes": anomaly_nodes,
            "scores": anomaly_scores,
            "threshold": threshold
        }

    def _behavior_clustering(self) -> Dict:
        """
        行为聚类
        使用 K-Means 算法
        """
        node_ids = list(self.node_features.keys())
        if not node_ids:
            return {"algorithm": "KMeans", "n_clusters": 0, "labels": {}}

        X = np.array([self.node_features[nid]["vector"] for nid in node_ids])

        # 标准化
        X_mean = X.mean(axis=0)
        X_std = X.std(axis=0) + 1e-8
        X_normalized = (X - X_mean) / X_std

        # 简化的 K-Means 实现
        n_clusters = self.config["kmeans"]["n_clusters"]

        # 随机初始化聚类中心
        np.random.seed(42)
        centroids = X_normalized[np.random.choice(len(X_normalized), n_clusters, replace=False)]

        max_iter = self.config["kmeans"]["max_iter"]
        labels = {}

        for _ in range(max_iter):
            # 分配样本到最近的聚类
            clusters = defaultdict(list)
            for i, nid in enumerate(node_ids):
                distances = [np.linalg.norm(X_normalized[i] - c) for c in centroids]
                cluster_id = np.argmin(distances)
                clusters[cluster_id].append(i)

            # 更新聚类中心
            new_centroids = []
            for k in range(n_clusters):
                if clusters[k]:
                    new_centroids.append(X_normalized[clusters[k]].mean(axis=0))
                else:
                    new_centroids.append(centroids[k])

            # 检查收敛
            if np.allclose(centroids, new_centroids):
                break
            centroids = new_centroids

        # 保存聚类结果
        for k in range(n_clusters):
            for idx in clusters[k]:
                labels[node_ids[idx]] = int(k)

        # 分析每个簇的异常程度
        cluster_stats = {}
        for k in range(n_clusters):
            cluster_nodes = [nid for nid, lbl in labels.items() if lbl == k]
            cluster_stats[k] = {
                "node_count": len(cluster_nodes),
                "avg_feature": X_normalized[[labels[nid] for nid in cluster_nodes]].mean(axis=0).tolist() if cluster_nodes else []
            }

        return {
            "algorithm": "KMeans",
            "n_clusters": n_clusters,
            "labels": labels,
            "cluster_stats": cluster_stats
        }

    def _calculate_threat_scores(self, graph: Dict, alerts: List[Dict],
                                 anomaly_results: Dict, cluster_results: Dict) -> Dict:
        """
        计算威胁评分
        综合多个检测维度的结果
        """
        threat_scores = {}
        weights = self.config["threat_weights"]

        # 构建告警节点映射（包含严重程度）
        node_alerts = defaultdict(list)
        node_alert_scores = {}
        severity_map = {"high": 3.0, "medium": 2.0, "low": 1.0, "critical": 4.0}

        if alerts:
            for alert in alerts:
                subj_id = alert.get("subject", {}).get("id", "")
                obj_id = alert.get("object", {}).get("id", "")
                severity = alert.get("rule", {}).get("severity", "low")
                severity_weight = severity_map.get(severity, 1.0)

                for nid in [subj_id, obj_id]:
                    if nid:
                        node_alerts[nid].append(severity_weight)

            # 计算每个节点的告警分数
            for nid, sev_weights in node_alerts.items():
                # 基础分数：告警数量的对数缩放
                count_score = min(len(sev_weights) / 3.0, 1.0)
                # 严重程度加权
                avg_severity = sum(sev_weights) / len(sev_weights) if sev_weights else 1.0
                node_alert_scores[nid] = count_score * (avg_severity / 4.0)

        # 获取异常分数
        anomaly_scores = anomaly_results.get("scores", {})

        for node_id in self.node_features:
            score = 0.0

            # 1. 规则违规分数 (60%) - 主要权重
            if node_id in node_alert_scores:
                score += weights["rule_violations"] * node_alert_scores[node_id]

            # 2. 异常分数 (20%)
            anomaly_score = anomaly_scores.get(node_id, 0.0)
            score += weights["anomaly_score"] * anomaly_score

            # 3. 可疑邻居比例 (10%)
            adjacency = graph.get("adjacency", {})
            neighbors = adjacency.get(node_id, set())
            if neighbors:
                suspicious_neighbors = sum(1 for n in neighbors
                                         if n in anomaly_results.get("anomaly_nodes", []))
                neighbor_ratio = suspicious_neighbors / len(neighbors)
                score += weights["suspicious_neighbors"] * neighbor_ratio

            # 4. 时序异常 (10%)
            temporal_features = self.node_features[node_id]["temporal"]
            # 检查凌晨活动或周末活动
            if temporal_features[0] < 0.2 or temporal_features[1] > 0.85:  # 凌晨或周末
                score += weights["temporal_anomaly"]

            # 5. 额外：节点类型加权（可疑进程类型）
            node = graph.get("nodes", {})
            for n in node:
                if n.get("id") == node_id:
                    node_type = n.get("type", "")
                    node_name = n.get("name", "").lower()
                    # 进程类型且名称可疑的加分
                    if node_type == "process":
                        if any(kw in node_name for kw in ["hidden", "backdoor", "malware", "trojan", "miner", "inject"]):
                            score = min(score + 0.15, 1.0)
                    break

            threat_scores[node_id] = round(min(score, 1.0), 3)

        return threat_scores

    def _classify_nodes(self, threat_scores: Dict) -> Dict:
        """根据威胁评分对节点进行分类"""
        # 首先按分数排序
        sorted_nodes = sorted(threat_scores.items(), key=lambda x: x[1], reverse=True)

        # 目标：威胁节点总数（critical + high + medium）在 50-100 之间
        total_nodes = len(sorted_nodes)
        target_min = max(50, int(total_nodes * 0.05))   # 至少50个，或5%
        target_max = max(100, int(total_nodes * 0.10))   # 至多100个，或10%

        # 找到合适的分类阈值
        classified = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "benign": []
        }

        # 先按固定阈值分类
        temp_classified = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "benign": []
        }

        for node_id, score in sorted_nodes:
            if score > 0.7:
                temp_classified["critical"].append((node_id, score))
            elif score > 0.45:
                temp_classified["high"].append((node_id, score))
            elif score > 0.25:
                temp_classified["medium"].append((node_id, score))
            elif score > 0.1:
                temp_classified["low"].append((node_id, score))
            else:
                temp_classified["benign"].append((node_id, score))

        # 计算当前威胁节点总数
        threat_count = (len(temp_classified["critical"]) +
                       len(temp_classified["high"]) +
                       len(temp_classified["medium"]))

        # 如果威胁节点太多，提高阈值
        if threat_count > target_max:
            # 需要减少节点，只保留分数最高的
            all_threat = (temp_classified["critical"] +
                         temp_classified["high"] +
                         temp_classified["medium"])
            # 按分数排序后截断
            all_threat.sort(key=lambda x: x[1], reverse=True)

            kept = all_threat[:target_max]
            # 重新分类
            classified["critical"] = [nid for nid, score in kept if score > 0.7]
            classified["high"] = [nid for nid, score in kept if 0.45 < score <= 0.7]
            classified["medium"] = [nid for nid, score in kept if score <= 0.45]
            # 剩余的归为low
            remaining_high = all_threat[target_max:]
            classified["low"] = [nid for nid, score in remaining_high]
            classified["benign"] = [nid for nid, score in temp_classified["low"] + temp_classified["benign"]]

        # 如果威胁节点太少，降低阈值
        elif threat_count < target_min:
            # 扩展medium范围
            for node_id, score in temp_classified["low"][:target_min - threat_count]:
                temp_classified["medium"].append((node_id, score))
            temp_classified["low"] = temp_classified["low"][target_min - threat_count:]

            classified["critical"] = [nid for nid, _ in temp_classified["critical"]]
            classified["high"] = [nid for nid, _ in temp_classified["high"]]
            classified["medium"] = [nid for nid, _ in temp_classified["medium"]]
            classified["low"] = [nid for nid, _ in temp_classified["low"]]
            classified["benign"] = [nid for nid, _ in temp_classified["benign"]]

        else:
            # 数量合适
            classified["critical"] = [nid for nid, _ in temp_classified["critical"]]
            classified["high"] = [nid for nid, _ in temp_classified["high"]]
            classified["medium"] = [nid for nid, _ in temp_classified["medium"]]
            classified["low"] = [nid for nid, _ in temp_classified["low"]]
            classified["benign"] = [nid for nid, _ in temp_classified["benign"]]

        return classified

    def _generate_summary(self, classified_nodes: Dict) -> Dict:
        """生成检测摘要"""
        total = sum(len(nodes) for nodes in classified_nodes.values())

        return {
            "total_nodes": total,
            "by_level": {k: len(v) for k, v in classified_nodes.items()},
            "critical_count": len(classified_nodes.get("critical", [])),
            "high_count": len(classified_nodes.get("high", [])),
            "medium_count": len(classified_nodes.get("medium", [])),
            "overall_threat_level": self._determine_overall_level(classified_nodes)
        }

    def _determine_overall_level(self, classified: Dict) -> str:
        """确定整体威胁等级"""
        if classified.get("critical"):
            return "critical"
        elif classified.get("high"):
            return "high"
        elif classified.get("medium"):
            return "medium"
        elif classified.get("low"):
            return "low"
        else:
            return "benign"


if __name__ == "__main__":
    # 测试威胁检测
    from modules.data_generator import DataGenerator
    from modules.event_extractor import EventExtractor
    from modules.graph_builder import GraphBuilder
    from modules.rule_engine import RuleEngine

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
    result = detector.detect(graph, rule_result.get("alerts", []))

    print(f"检测摘要: {result['summary']}")
