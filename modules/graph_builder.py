# -*- coding: utf-8 -*-
"""
图构建模块
基于事件信息构建关系图，并进行去噪处理
"""

import json
from typing import List, Dict, Any, Set, Tuple
from collections import defaultdict, Counter
from datetime import datetime


class GraphBuilder:
    """关系图构建器"""

    def __init__(self, denoise_config: Dict = None):
        """
        初始化图构建器

        Args:
            denoise_config: 去噪配置
        """
        # 默认去噪配置
        self.denoise_config = denoise_config or {
            "high_freq_threshold": 50,      # 高频事件阈值（次/小时）
            "min_process_duration": 1,      # 最小进程生命周期（秒）
            "min_node_degree": 1,           # 最小节点度数
            "filter_system_services": True  # 过滤系统服务
        }

        # 系统服务列表（过滤）
        self.system_services = {
            "systemd", "init", "kthreadd", "ksoftirqd",
            "cron", "anacron"
        }

        # 图数据结构
        self.nodes = {}      # {node_id: Node}
        self.edges = {}      # {edge_id: Edge}
        self.adjacency = defaultdict(set)  # {node_id: set(neighbor_ids)}

    def build_graph(self, events: List[Dict]) -> Dict:
        """
        从事件列表构建关系图

        Args:
            events: 事件列表

        Returns:
            Dict: 包含节点、边和统计信息的图数据
        """
        print("开始构建关系图...")

        # 1. 提取节点和边
        self._extract_nodes_and_edges(events)

        # 2. 去噪处理
        if self.denoise_config.get("filter_system_services"):
            self._filter_system_services()

        self._remove_high_frequency_edges(events)
        self._remove_isolated_nodes()

        # 3. 计算图的统计信息
        stats = self._calculate_graph_stats()

        # 4. 构建返回结果（将 neighbors 转换为列表以支持 JSON 序列化）
        nodes_for_json = []
        for node in self.nodes.values():
            node_copy = node.copy()
            node_copy["neighbors"] = list(node.get("neighbors", set()))
            nodes_for_json.append(node_copy)

        # 将 adjacency 中的 set 也转换为列表
        adjacency_for_json = {
            k: list(v) for k, v in self.adjacency.items()
        }

        result = {
            "nodes": nodes_for_json,
            "edges": list(self.edges.values()),
            "adjacency": adjacency_for_json,
            "statistics": stats
        }

        print(f"图构建完成: {len(self.nodes)} 节点, {len(self.edges)} 边")
        return result

    def _extract_nodes_and_edges(self, events: List[Dict]):
        """从事件中提取节点和边"""
        for event in events:
            # 提取主体节点
            subject = event.get("subject", {})
            if subject:
                subject_id = subject.get("id", "")
                if subject_id:
                    self._add_or_update_node(subject_id, subject, event.get("label", "unknown"))

            # 提取客体节点
            obj = event.get("object", {})
            if obj:
                obj_id = obj.get("id", "")
                if obj_id:
                    self._add_or_update_node(obj_id, obj, event.get("label", "unknown"))

            # 创建边
            if subject and obj:
                subject_id = subject.get("id", "")
                obj_id = obj.get("id", "")
                if subject_id and obj_id:
                    self._add_edge(subject_id, obj_id, event)

    def _add_or_update_node(self, node_id: str, entity_data: Dict, label: str = "unknown"):
        """添加或更新节点"""
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id,
                "type": entity_data.get("type", "unknown"),
                "name": entity_data.get("name", entity_data.get("path", "")),
                "attributes": entity_data,
                "label": label,
                "degree": 0,
                "neighbors": set()
            }

        # 更新节点属性
        node = self.nodes[node_id]
        for key, value in entity_data.items():
            if key not in node["attributes"]:
                node["attributes"][key] = value

    def _add_edge(self, source_id: str, target_id: str, event: Dict):
        """添加边"""
        edge_id = f"{source_id}->{target_id}"

        # 如果边已存在，更新权重和事件列表
        if edge_id in self.edges:
            edge = self.edges[edge_id]
            edge["weight"] += 1
            edge["event_ids"].append(event.get("event_id", ""))
            edge["timestamps"].append(event.get("timestamp", ""))
            edge["actions"].append(event.get("action", "unknown"))
        else:
            self.edges[edge_id] = {
                "id": edge_id,
                "source": source_id,
                "target": target_id,
                "action": event.get("action", "unknown"),
                "weight": 1,
                "event_ids": [event.get("event_id", "")],
                "timestamps": [event.get("timestamp", "")],
                "actions": [event.get("action", "unknown")],
                "label": event.get("label", "unknown")
            }

        # 更新邻接表
        self.adjacency[source_id].add(target_id)
        self.adjacency[target_id].add(source_id)

        # 更新节点度数
        if source_id in self.nodes:
            self.nodes[source_id]["degree"] = len(self.adjacency[source_id])
            self.nodes[source_id]["neighbors"].add(target_id)
        if target_id in self.nodes:
            self.nodes[target_id]["degree"] = len(self.adjacency[target_id])
            self.nodes[target_id]["neighbors"].add(source_id)

    def _filter_system_services(self):
        """过滤系统服务"""
        nodes_to_remove = []

        for node_id, node in self.nodes.items():
            node_name = node.get("name", "")
            if node_name in self.system_services:
                nodes_to_remove.append(node_id)

        for node_id in nodes_to_remove:
            self._remove_node(node_id)

        if nodes_to_remove:
            print(f"过滤系统服务节点: {len(nodes_to_remove)} 个")

    def _remove_high_frequency_edges(self, events: List[Dict]):
        """移除高频正常边"""
        # 统计每个 (source, target, action) 组合的出现次数
        edge_counter = Counter()

        for edge in self.edges.values():
            # 获取主要动作
            main_action = Counter(edge["actions"]).most_common(1)[0][0] if edge["actions"] else "unknown"
            key = (edge["source"], edge["target"], main_action)
            edge_counter[key] = edge["weight"]

        # 标记需要移除的高频边
        threshold = self.denoise_config["high_freq_threshold"]
        edges_to_remove = []

        for edge_id, edge in self.edges.items():
            # 获取主要动作
            main_action = Counter(edge["actions"]).most_common(1)[0][0] if edge["actions"] else "unknown"
            key = (edge["source"], edge["target"], main_action)

            # 如果是高频边且标记为正常，则移除
            if edge_counter[key] > threshold and edge.get("label") == "benign":
                edges_to_remove.append(edge_id)

        for edge_id in edges_to_remove:
            self._remove_edge(edge_id)

        if edges_to_remove:
            print(f"移除高频正常边: {len(edges_to_remove)} 条")

    def _remove_isolated_nodes(self):
        """移除孤立节点"""
        nodes_to_remove = []

        min_degree = self.denoise_config.get("min_node_degree", 1)

        for node_id, node in self.nodes.items():
            if node["degree"] < min_degree:
                nodes_to_remove.append(node_id)

        for node_id in nodes_to_remove:
            self._remove_node(node_id)

        if nodes_to_remove:
            print(f"移除孤立节点: {len(nodes_to_remove)} 个")

    def _remove_node(self, node_id: str):
        """移除节点及其相关边"""
        if node_id not in self.nodes:
            return

        # 移除相关的边
        edges_to_remove = []
        for edge_id, edge in self.edges.items():
            if edge["source"] == node_id or edge["target"] == node_id:
                edges_to_remove.append(edge_id)

        for edge_id in edges_to_remove:
            self._remove_edge(edge_id)

        # 移除邻接关系
        for neighbor_id in list(self.adjacency[node_id]):
            if neighbor_id in self.adjacency:
                self.adjacency[neighbor_id].discard(node_id)

        del self.adjacency[node_id]
        del self.nodes[node_id]

    def _remove_edge(self, edge_id: str):
        """移除边"""
        if edge_id not in self.edges:
            return

        edge = self.edges[edge_id]
        source_id = edge["source"]
        target_id = edge["target"]

        # 更新邻接表
        if source_id in self.adjacency:
            self.adjacency[source_id].discard(target_id)
        if target_id in self.adjacency:
            self.adjacency[target_id].discard(source_id)

        # 更新节点度数
        if source_id in self.nodes:
            self.nodes[source_id]["degree"] = len(self.adjacency[source_id])
            self.nodes[source_id]["neighbors"].discard(target_id)
        if target_id in self.nodes:
            self.nodes[target_id]["degree"] = len(self.adjacency[target_id])
            self.nodes[target_id]["neighbors"].discard(source_id)

        del self.edges[edge_id]

    def _calculate_graph_stats(self) -> Dict:
        """计算图的统计信息"""
        if not self.nodes:
            return {
                "node_count": 0,
                "edge_count": 0,
                "avg_degree": 0,
                "max_degree": 0,
                "node_types": {},
                "edge_types": {}
            }

        degrees = [node["degree"] for node in self.nodes.values()]

        # 统计节点类型
        node_types = Counter()
        for node in self.nodes.values():
            node_types[node["type"]] += 1

        # 统计边类型
        edge_types = Counter()
        for edge in self.edges.values():
            edge_types[edge["action"]] += 1

        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "avg_degree": sum(degrees) / len(degrees) if degrees else 0,
            "max_degree": max(degrees) if degrees else 0,
            "density": len(self.edges) / (len(self.nodes) * (len(self.nodes) - 1) / 2) if len(self.nodes) > 1 else 0,
            "node_types": dict(node_types),
            "edge_types": dict(edge_types)
        }

    def get_node_neighbors(self, node_id: str, hop: int = 1) -> Set[str]:
        """
        获取节点的 k-hop 邻居

        Args:
            node_id: 节点ID
            hop: 跳数

        Returns:
            Set[str]: 邻居节点ID集合
        """
        if node_id not in self.nodes:
            return set()

        visited = {node_id}
        current_level = {node_id}

        for _ in range(hop):
            next_level = set()
            for nid in current_level:
                next_level.update(self.adjacency.get(nid, set()))
            current_level = next_level - visited
            visited.update(current_level)

        visited.remove(node_id)
        return visited

    def get_shortest_path(self, source_id: str, target_id: str) -> List[str]:
        """
        获取两个节点之间的最短路径

        Args:
            source_id: 源节点ID
            target_id: 目标节点ID

        Returns:
            List[str]: 路径节点ID列表
        """
        if source_id not in self.nodes or target_id not in self.nodes:
            return []

        # BFS 寻找最短路径
        from collections import deque

        queue = deque([(source_id, [source_id])])
        visited = {source_id}

        while queue:
            node_id, path = queue.popleft()

            if node_id == target_id:
                return path

            for neighbor_id in self.adjacency.get(node_id, set()):
                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    queue.append((neighbor_id, path + [neighbor_id]))

        return []

    def find_connected_components(self) -> List[List[str]]:
        """
        查找连通分量

        Returns:
            List[List[str]]: 连通分量列表
        """
        visited = set()
        components = []

        for node_id in self.nodes:
            if node_id not in visited:
                component = []
                stack = [node_id]

                while stack:
                    nid = stack.pop()
                    if nid not in visited:
                        visited.add(nid)
                        component.append(nid)
                        stack.extend(self.adjacency.get(nid, set()) - visited)

                components.append(component)

        return components

    def export_to_networkx_format(self) -> Tuple[List, List]:
        """
        导出为 NetworkX 格式

        Returns:
            Tuple[List, List]: (节点列表, 边列表)
        """
        nodes = [
            (nid, {
                "type": node["type"],
                "name": node["name"],
                "label": node["label"],
                "degree": node["degree"]
            })
            for nid, node in self.nodes.items()
        ]

        edges = [
            (edge["source"], edge["target"], {
                "action": edge["action"],
                "weight": edge["weight"],
                "label": edge["label"]
            })
            for edge in self.edges.values()
        ]

        return nodes, edges


if __name__ == "__main__":
    # 测试图构建
    from modules.data_generator import DataGenerator
    from modules.event_extractor import EventExtractor

    # 生成测试数据
    print("生成测试数据...")
    generator = DataGenerator()
    log_data = generator.generate(total_events=1000)

    # 提取事件
    print("提取事件...")
    extractor = EventExtractor()
    events = extractor.extract_from_logs(log_data)

    # 构建图
    print("构建图...")
    builder = GraphBuilder()
    graph = builder.build_graph(events)

    print(f"图统计: {json.dumps(graph['statistics'], indent=2, ensure_ascii=False)}")
