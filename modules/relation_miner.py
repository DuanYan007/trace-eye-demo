# -*- coding: utf-8 -*-
"""
关系挖掘模块
基于异常点挖掘潜在可疑关系
"""

from typing import List, Dict, Any, Set, Tuple
from datetime import datetime
from collections import defaultdict


class RelationMiner:
    """关系挖掘器 - 挖掘异常点周围的潜在可疑关系"""

    def __init__(self, graph: Dict = None):
        """
        初始化关系挖掘器

        Args:
            graph: 图数据，包含节点、边和邻接表
        """
        # 挖掘配置
        self.config = {
            "hop_distance": 2,          # 扩展跳数
            "correlation_threshold": 0.5,  # 关联度阈值
            "time_window": 300,         # 时间窗口（秒）
            "min_suspicious_neighbors": 2,  # 最小可疑邻居数
            "max_anomaly_nodes": 600,
            "max_neighbors_per_node": 80,
            "max_relations": 2500,
            "max_subgraphs": 80,
            "max_path_depth": 2
        }
        self.graph = {"nodes": [], "edges": [], "adjacency": {}}
        self.node_index = {}
        self.edge_index = {}
        self.adjacency = {}
        self.set_graph(graph or self.graph)

    def set_graph(self, graph: Dict):
        """设置图数据"""
        self.graph = graph or {"nodes": [], "edges": [], "adjacency": {}}
        self._prepare_indexes()

    def _prepare_indexes(self):
        """为节点、边和邻接表建立索引，避免关系计算时反复全图扫描。"""
        self.node_index = {
            node.get("id", ""): node
            for node in self.graph.get("nodes", [])
            if node.get("id")
        }
        self.adjacency = {
            node_id: set(neighbors or [])
            for node_id, neighbors in self.graph.get("adjacency", {}).items()
        }
        self.edge_index = {}
        for edge in self.graph.get("edges", []):
            source = edge.get("source", "")
            target = edge.get("target", "")
            if not source or not target:
                edge_id = edge.get("id", "")
                if "->" in edge_id:
                    source, target = edge_id.split("->", 1)
            if source and target:
                self.edge_index[(source, target)] = edge
                self.edge_index[(target, source)] = edge

    def mine_suspicious_relations(self, anomaly_nodes: List[str]) -> List[Dict]:
        """
        挖掘可疑关系

        Args:
            anomaly_nodes: 异常节点ID列表

        Returns:
            List[Dict]: 挖掘出的可疑关系列表
        """
        print(f"开始挖掘可疑关系，异常节点数: {len(anomaly_nodes)}")

        suspicious_relations = []
        unique_anomaly_nodes = []
        seen_anomaly_nodes = set()
        for node_id in anomaly_nodes:
            if node_id in self.node_index and node_id not in seen_anomaly_nodes:
                seen_anomaly_nodes.add(node_id)
                unique_anomaly_nodes.append(node_id)

        unique_anomaly_nodes.sort(
            key=lambda nid: len(self.adjacency.get(nid, set())),
            reverse=True
        )
        selected_anomaly_nodes = unique_anomaly_nodes[:self.config["max_anomaly_nodes"]]
        seen_pairs = set()
        evaluated_pairs = 0

        for anomaly_node in selected_anomaly_nodes:
            # 1. 扩展 k-hop 邻居
            neighbors = self._get_k_hop_neighbors(anomaly_node, self.config["hop_distance"])
            neighbors = sorted(
                (neighbor for neighbor in neighbors if neighbor in self.node_index),
                key=lambda nid: (
                    self._get_edge_info(anomaly_node, nid) is None,
                    -len(self.adjacency.get(nid, set()))
                )
            )[:self.config["max_neighbors_per_node"]]

            # 2. 计算关联度
            for neighbor in neighbors:
                pair_key = tuple(sorted((anomaly_node, neighbor)))
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)
                evaluated_pairs += 1
                correlation = self._calculate_correlation(anomaly_node, neighbor)

                if correlation >= self.config["correlation_threshold"]:
                    # 3. 构建可疑关系
                    relation = self._build_suspicious_relation(anomaly_node, neighbor, correlation)
                    suspicious_relations.append(relation)
                    if len(suspicious_relations) >= self.config["max_relations"]:
                        break
            if len(suspicious_relations) >= self.config["max_relations"]:
                break

        # 4. 构建可疑子图
        suspicious_subgraphs = self._build_suspicious_subgraphs(selected_anomaly_nodes, suspicious_relations)

        result = {
            "suspicious_relations": suspicious_relations,
            "suspicious_subgraphs": suspicious_subgraphs,
            "statistics": {
                "total_relations": len(suspicious_relations),
                "total_subgraphs": len(suspicious_subgraphs),
                "input_anomaly_nodes": len(anomaly_nodes),
                "selected_anomaly_nodes": len(selected_anomaly_nodes),
                "evaluated_pairs": evaluated_pairs,
                "avg_correlation": sum(r["correlation"] for r in suspicious_relations) / len(suspicious_relations) if suspicious_relations else 0
            }
        }

        print(f"挖掘完成: 发现 {len(suspicious_relations)} 条可疑关系")
        return result

    def _get_k_hop_neighbors(self, node_id: str, k: int) -> Set[str]:
        """
        获取节点的 k-hop 邻居

        Args:
            node_id: 节点ID
            k: 跳数

        Returns:
            Set[str]: 邻居节点ID集合
        """
        if node_id not in self.adjacency:
            return set()

        visited = {node_id}
        current_level = {node_id}

        for _ in range(k):
            next_level = set()
            for nid in current_level:
                next_level.update(self.adjacency.get(nid, set()))
            current_level = next_level - visited
            visited.update(current_level)

        visited.remove(node_id)
        return visited

    def _calculate_correlation(self, node_a: str, node_b: str) -> float:
        """
        计算两个节点之间的关联度

        Args:
            node_a: 节点A的ID
            node_b: 节点B的ID

        Returns:
            float: 关联度分数 (0-1)
        """
        # 获取节点信息
        node_a_info = self._get_node_info(node_a)
        node_b_info = self._get_node_info(node_b)

        if not node_a_info or not node_b_info:
            return 0.0

        # 计算多个维度的关联度
        scores = {
            "structural": self._structural_correlation(node_a, node_b),
            "semantic": self._semantic_correlation(node_a_info, node_b_info),
            "temporal": self._temporal_correlation(node_a, node_b),
            "path": self._path_correlation(node_a, node_b)
        }

        # 加权平均
        weights = {"structural": 0.3, "semantic": 0.3, "temporal": 0.2, "path": 0.2}

        correlation = sum(scores[k] * weights[k] for k in scores)
        return round(correlation, 3)

    def _get_node_info(self, node_id: str) -> Dict:
        """获取节点信息"""
        return self.node_index.get(node_id)

    def _get_edge_info(self, source: str, target: str) -> Dict:
        """获取边信息"""
        return self.edge_index.get((source, target))

    def _structural_correlation(self, node_a: str, node_b: str) -> float:
        """
        计算结构关联度
        基于共享邻居比例和公共边
        """
        neighbors_a = self.adjacency.get(node_a, set())
        neighbors_b = self.adjacency.get(node_b, set())

        if not neighbors_a or not neighbors_b:
            return 0.0

        # Jaccard相似度
        intersection = len(neighbors_a & neighbors_b)
        union = len(neighbors_a | neighbors_b)

        if union == 0:
            return 0.0

        return intersection / union

    def _semantic_correlation(self, node_a: Dict, node_b: Dict) -> float:
        """
        计算语义关联度
        基于节点属性和类型
        """
        score = 0.0

        # 类型关联
        type_a = node_a.get("type", "")
        type_b = node_b.get("type", "")

        # 某些类型对有高关联度
        high_corr_pairs = {
            ("process", "file"),
            ("process", "socket"),
            ("file", "process")
        }

        if (type_a, type_b) in high_corr_pairs or (type_b, type_a) in high_corr_pairs:
            score += 0.5

        # 标签关联（都是可疑或恶意）
        label_a = node_a.get("label", "")
        label_b = node_b.get("label", "")

        if label_a == label_b and label_a in ["malicious", "suspicious"]:
            score += 0.3

        # 名称相似性
        name_a = node_a.get("name", "").lower()
        name_b = node_b.get("name", "").lower()

        if name_a and name_b:
            # 检查是否有共同前缀或后缀
            if (name_a in name_b or name_b in name_a or
                name_a.split(".")[0] == name_b.split(".")[0]):
                score += 0.2

        return min(score, 1.0)

    def _temporal_correlation(self, node_a: str, node_b: str) -> float:
        """
        计算时序关联度
        基于事件时间接近程度
        """
        edge = self._get_edge_info(node_a, node_b)
        if not edge:
            return 0.0

        timestamps = edge.get("timestamps", [])
        if not timestamps or len(timestamps) < 2:
            return 0.0

        # 解析时间戳；只需相邻最小间隔，避免大量时间戳时做 O(T^2) 两两比较。
        times = []
        for ts in timestamps[:40]:
            try:
                if ts.endswith("Z"):
                    ts = ts[:-1]
                times.append(datetime.fromisoformat(ts))
            except:
                continue

        if len(times) < 2:
            return 0.0

        # 计算时间间隔
        times.sort()
        min_diff = min(
            abs((times[i] - times[i - 1]).total_seconds())
            for i in range(1, len(times))
        )

        # 时间越接近，关联度越高
        time_window = self.config["time_window"]
        if min_diff <= time_window:
            return 1.0 - (min_diff / time_window)

        return 0.0

    def _path_correlation(self, node_a: str, node_b: str) -> float:
        """
        计算路径关联度
        基于最短路径长度
        """
        # BFS 查找最短路径
        from collections import deque

        queue = deque([(node_a, 0)])
        visited = {node_a}

        while queue:
            node, dist = queue.popleft()

            if node == node_b:
                # 距离越短，关联度越高
                return 1.0 / (1 + dist)

            if dist >= self.config["max_path_depth"]:
                continue

            for neighbor in self.adjacency.get(node, set()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, dist + 1))

        return 0.0

    def _build_suspicious_relation(self, node_a: str, node_b: str, correlation: float) -> Dict:
        """构建可疑关系对象"""
        node_a_info = self._get_node_info(node_a)
        node_b_info = self._get_node_info(node_b)
        edge = self._get_edge_info(node_a, node_b)

        return {
            "id": f"rel_{node_a}_{node_b}",
            "source": node_a,
            "target": node_b,
            "source_type": node_a_info.get("type", "") if node_a_info else "",
            "target_type": node_b_info.get("type", "") if node_b_info else "",
            "correlation": correlation,
            "actions": edge.get("actions", []) if edge else [],
            "event_count": edge.get("weight", 0) if edge else 0,
            "timestamps": edge.get("timestamps", []) if edge else []
        }

    def _build_suspicious_subgraphs(self, anomaly_nodes: List[str],
                                    suspicious_relations: List[Dict]) -> List[Dict]:
        """
        构建可疑子图
        将相关的可疑关系聚合成子图
        """
        # 使用简单的连通分量算法
        adjacency = defaultdict(set)

        for rel in suspicious_relations:
            adjacency[rel["source"]].add(rel["target"])
            adjacency[rel["target"]].add(rel["source"])

        # 查找连通分量
        visited = set()
        subgraphs = []

        for node in adjacency:
            if node not in visited:
                component = self._bfs_component(node, adjacency, visited)
                if len(component) >= 2:  # 至少包含2个节点
                    subgraphs.append(self._build_subgraph(component, suspicious_relations))
                    if len(subgraphs) >= self.config["max_subgraphs"]:
                        break

        return subgraphs

    def _bfs_component(self, start: str, adjacency: Dict, visited: Set) -> Set[str]:
        """BFS 查找连通分量"""
        from collections import deque

        component = set()
        queue = deque([start])
        visited.add(start)

        while queue:
            node = queue.popleft()
            component.add(node)

            for neighbor in adjacency.get(node, set()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)

        return component

    def _build_subgraph(self, nodes: Set[str], suspicious_relations: List[Dict]) -> Dict:
        """构建子图对象"""
        # 获取子图内的边
        subgraph_edges = [
            rel for rel in suspicious_relations
            if rel["source"] in nodes and rel["target"] in nodes
        ]

        # 计算子图统计
        avg_correlation = sum(e["correlation"] for e in subgraph_edges) / len(subgraph_edges) if subgraph_edges else 0

        return {
            "id": f"subgraph_{'_'.join(sorted(list(nodes))[:3])}",
            "nodes": list(nodes),
            "node_count": len(nodes),
            "edges": subgraph_edges,
            "edge_count": len(subgraph_edges),
            "avg_correlation": round(avg_correlation, 3),
            "threat_score": self._calculate_subgraph_threat(nodes, subgraph_edges)
        }

    def _calculate_subgraph_threat(self, nodes: Set[str], edges: List[Dict]) -> float:
        """
        计算子图威胁评分
        考虑节点数、边数、平均关联度等因素
        """
        if not edges:
            return 0.0

        # 基础分：节点数和边数
        base_score = min(len(nodes) * 0.1 + len(edges) * 0.1, 0.5)

        # 关联度分
        avg_corr = sum(e["correlation"] for e in edges) / len(edges)
        corr_score = avg_corr * 0.3

        # 恶意节点比例
        malicious_count = 0
        for node in nodes:
            node_info = self.node_index.get(node)
            if node_info and node_info.get("label") == "malicious":
                malicious_count += 1

        malicious_ratio = malicious_count / len(nodes) if nodes else 0
        malicious_score = malicious_ratio * 0.2

        total_score = base_score + corr_score + malicious_score
        return round(min(total_score, 1.0), 3)


if __name__ == "__main__":
    # 测试关系挖掘
    from modules.data_generator import DataGenerator
    from modules.event_extractor import EventExtractor
    from modules.graph_builder import GraphBuilder

    print("生成测试数据...")
    generator = DataGenerator()
    log_data = generator.generate(total_events=1000)

    print("提取事件...")
    extractor = EventExtractor()
    events = extractor.extract_from_logs(log_data)

    print("构建图...")
    builder = GraphBuilder()
    graph = builder.build_graph(events)

    # 模拟异常节点
    anomaly_nodes = [n["id"] for n in graph["nodes"] if n.get("label") == "malicious"][:5]

    print("挖掘可疑关系...")
    miner = RelationMiner(graph)
    result = miner.mine_suspicious_relations(anomaly_nodes)

    print(f"挖掘结果: {result['statistics']}")
