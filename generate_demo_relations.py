# -*- coding: utf-8 -*-
"""
生成关系挖掘演示数据
基于已有的威胁检测结果生成可疑关系和子图
"""

import json
import random
from collections import defaultdict

def load_json(filepath):
    """加载 JSON 文件"""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return None

def save_json(filepath, data):
    """保存 JSON 文件"""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def generate_suspicious_relations(graph_data, threat_data):
    """生成可疑关系数据"""
    # 获取异常节点
    anomaly_nodes = threat_data.get("anomaly_detection", {}).get("anomaly_nodes", [])
    threat_scores = threat_data.get("threat_scores", {})

    if not anomaly_nodes:
        anomaly_nodes = list(threat_scores.keys())[:20]

    # 获取图邻接信息
    adjacency = {}
    for node in graph_data.get("nodes", []):
        node_id = node.get("id")
        neighbors = node.get("neighbors", [])
        if node_id and neighbors:
            adjacency[node_id] = set(neighbors)

    # 获取边信息（用于权重和时间戳）
    edge_info = {}
    for edge in graph_data.get("edges", []):
        edge_id = f"{edge.get('source')}->{edge.get('target')}"
        edge_info[edge_id] = {
            "weight": edge.get("weight", 1),
            "timestamps": edge.get("timestamps", []),
            "actions": edge.get("actions", [])
        }

    suspicious_relations = []

    # 为每个异常节点生成可疑关系
    for anomaly_node in anomaly_nodes[:15]:  # 限制异常节点数量
        neighbors = adjacency.get(anomaly_node, set())

        # 如果没有邻居，跳过
        if not neighbors:
            continue

        # 从邻居中选择高关联度的节点
        candidate_neighbors = list(neighbors)[:30]  # 增加候选数量
        random.shuffle(candidate_neighbors)  # 随机化

        for neighbor in candidate_neighbors:
            if neighbor == anomaly_node:
                continue

            # 计算关联度（添加随机性）
            correlation = calculate_correlation(
                anomaly_node, neighbor, adjacency, threat_scores, edge_info
            )

            # 降低阈值以获得更多关系
            if correlation >= 0.3:
                relation = build_relation(
                    anomaly_node, neighbor, correlation,
                    graph_data, edge_info
                )
                suspicious_relations.append(relation)

    # 按关联度排序
    suspicious_relations.sort(key=lambda x: x["correlation"], reverse=True)

    # 去重（保留相同节点对中关联度最高的）
    seen_pairs = set()
    unique_relations = []
    for rel in suspicious_relations:
        pair = tuple(sorted([rel["source"], rel["target"]]))
        if pair not in seen_pairs:
            seen_pairs.add(pair)
            unique_relations.append(rel)

    # 限制数量并确保有足够的数据
    suspicious_relations = unique_relations[:150]

    # 如果数据太少，添加一些模拟关系
    if len(suspicious_relations) < 50:
        for anomaly_node in anomaly_nodes[:5]:
            for i in range(10):
                # 生成一个随机邻居ID
                fake_neighbor = f"node_{random.randint(10000, 99999)}"
                correlation = random.uniform(0.4, 0.95)

                suspicious_relations.append({
                    "id": f"rel_{anomaly_node}_{fake_neighbor}",
                    "source": anomaly_node,
                    "target": fake_neighbor,
                    "source_type": "process",
                    "target_type": random.choice(["process", "file", "socket"]),
                    "correlation": round(correlation, 3),
                    "actions": ["connect", "read"],
                    "event_count": random.randint(1, 5),
                    "timestamps": ["2025-03-20T10:00:00Z"]
                })

    return suspicious_relations[:150]

def calculate_correlation(node_a, node_b, adjacency, threat_scores, edge_info):
    """计算两个节点之间的关联度"""
    scores = {
        "structural": 0.0,
        "semantic": 0.0,
        "temporal": 0.0,
        "path": 0.0
    }

    # 结构关联度 - Jaccard相似度
    neighbors_a = adjacency.get(node_a, set())
    neighbors_b = adjacency.get(node_b, set())

    if neighbors_a and neighbors_b:
        intersection = len(neighbors_a & neighbors_b)
        union = len(neighbors_a | neighbors_b)
        scores["structural"] = intersection / union if union > 0 else 0.0

    # 语义关联度
    # 获取节点信息
    node_a_info = get_node_info(node_a, None)  # 简化
    node_b_info = get_node_info(node_b, None)

    # 类型关联
    type_pairs = [("process", "file"), ("process", "socket"), ("file", "process")]
    if (node_a_info.get("type"), node_b_info.get("type")) in type_pairs or \
       (node_b_info.get("type"), node_a_info.get("type")) in type_pairs:
        scores["semantic"] += 0.4

    # 威胁评分关联
    score_a = threat_scores.get(node_a, 0)
    score_b = threat_scores.get(node_b, 0)
    if score_a > 0.5 and score_b > 0.5:
        scores["semantic"] += 0.3

    # 路径关联度（简化）
    # 如果直接相连，路径关联度高
    edge_id = f"{node_a}->{node_b}"
    reverse_edge_id = f"{node_b}->{node_a}"
    if edge_id in edge_info or reverse_edge_id in edge_info:
        scores["path"] = 1.0
    elif neighbors_a and node_b in neighbors_a:
        scores["path"] = 1.0
    elif neighbors_b and node_a in neighbors_b:
        scores["path"] = 1.0

    # 时序关联度（模拟）
    scores["temporal"] = random.uniform(0.3, 0.9)

    # 加权平均
    weights = {"structural": 0.3, "semantic": 0.3, "temporal": 0.2, "path": 0.2}
    correlation = sum(scores[k] * weights[k] for k in scores)

    return round(min(correlation, 1.0), 3)

def get_node_info(node_id, graph_data):
    """获取节点信息（简化版）"""
    # 根据ID推断类型
    if node_id.startswith("proc_"):
        return {"type": "process", "name": node_id}
    elif node_id.startswith("file_"):
        return {"type": "file", "name": node_id}
    elif node_id.startswith("socket_") or node_id.startswith("net_"):
        return {"type": "socket", "name": node_id}
    return {"type": "unknown", "name": node_id}

def build_relation(node_a, node_b, correlation, graph_data, edge_info):
    """构建可疑关系对象"""
    node_a_info = get_node_info(node_a, None)
    node_b_info = get_node_info(node_b, None)

    # 查找边信息
    edge_id = f"{node_a}->{node_b}"
    reverse_edge_id = f"{node_b}->{node_a}"
    edge = edge_info.get(edge_id) or edge_info.get(reverse_edge_id) or {}

    return {
        "id": f"rel_{node_a}_{node_b}",
        "source": node_a,
        "target": node_b,
        "source_type": node_a_info.get("type", "unknown"),
        "target_type": node_b_info.get("type", "unknown"),
        "correlation": correlation,
        "actions": edge.get("actions", ["connect", "read", "write"][:random.randint(1, 3)]),
        "event_count": edge.get("weight", random.randint(1, 10)),
        "timestamps": edge.get("timestamps", ["2025-03-20T10:00:00Z"])
    }

def generate_suspicious_subgraphs(suspicious_relations, anomaly_nodes):
    """生成可疑子图"""
    if not suspicious_relations:
        return []

    # 构建邻接表
    adjacency = defaultdict(set)
    for rel in suspicious_relations:
        adjacency[rel["source"]].add(rel["target"])
        adjacency[rel["target"]].add(rel["source"])

    # 添加异常节点之间的连接
    for i, node_a in enumerate(anomaly_nodes[:10]):
        for node_b in anomaly_nodes[i+1:10]:
            if node_b in adjacency.get(node_a, set()):
                adjacency[node_a].add(node_b)
                adjacency[node_b].add(node_a)

    # 查找连通分量作为子图
    visited = set()
    subgraphs = []

    for node in list(adjacency.keys())[:100]:  # 增加搜索范围
        if node not in visited:
            component = bfs_component(node, adjacency, visited)
            if len(component) >= 3:  # 至少3个节点
                subgraph = build_subgraph(component, suspicious_relations)
                subgraphs.append(subgraph)

    # 如果子图太少，手动创建一些
    if len(subgraphs) < 5:
        for i in range(5):
            # 创建一个包含异常节点和几个可疑节点的子图
            if i < len(anomaly_nodes):
                base_node = anomaly_nodes[i]
                related_nodes = [
                    n for n in list(adjacency.keys())
                    if n != base_node and random.random() > 0.7
                ][:random.randint(3, 8)]

                subgraph_nodes = [base_node] + related_nodes
                subgraph = build_subgraph(subgraph_nodes, suspicious_relations)
                subgraphs.append(subgraph)

    # 按威胁评分排序
    subgraphs.sort(key=lambda x: x["threat_score"], reverse=True)

    return subgraphs[:12]  # 返回前12个子图

def bfs_component(start, adjacency, visited):
    """BFS查找连通分量"""
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

def build_subgraph(nodes, suspicious_relations):
    """构建子图对象"""
    # 获取子图内的边
    subgraph_edges = []
    node_set = set(nodes)

    for rel in suspicious_relations:
        if rel["source"] in node_set and rel["target"] in node_set:
            subgraph_edges.append(rel)

    # 计算子图统计
    avg_correlation = (
        sum(e["correlation"] for e in subgraph_edges) / len(subgraph_edges)
        if subgraph_edges else 0
    )

    # 计算威胁评分
    base_score = min(len(nodes) * 0.05, 0.3)
    corr_score = avg_correlation * 0.4
    malicious_score = min(len(nodes) * 0.03, 0.3)

    threat_score = round(base_score + corr_score + malicious_score, 3)

    return {
        "id": f"subgraph_{'_'.join(sorted(list(nodes))[:3])}",
        "nodes": list(nodes),
        "node_count": len(nodes),
        "edges": subgraph_edges,
        "edge_count": len(subgraph_edges),
        "avg_correlation": round(avg_correlation, 3),
        "threat_score": threat_score
    }

def main():
    import os

    demo_dir = os.path.join(os.path.dirname(__file__), "data", "demo")

    print("加载图数据...")
    graph_data = load_json(os.path.join(demo_dir, "data_graph.json"))

    print("加载威胁数据...")
    threat_data = load_json(os.path.join(demo_dir, "data_threat.json"))

    if not graph_data or not threat_data:
        print("错误：无法加载基础数据")
        return

    print("生成可疑关系...")
    suspicious_relations = generate_suspicious_relations(graph_data, threat_data)

    print(f"  生成了 {len(suspicious_relations)} 条可疑关系")

    print("生成可疑子图...")
    anomaly_nodes = threat_data.get("anomaly_detection", {}).get("anomaly_nodes", [])
    suspicious_subgraphs = generate_suspicious_subgraphs(
        suspicious_relations, anomaly_nodes
    )

    print(f"  生成了 {len(suspicious_subgraphs)} 个可疑子图")

    # 计算统计
    total_relations = len(suspicious_relations)
    total_subgraphs = len(suspicious_subgraphs)
    avg_correlation = (
        sum(r["correlation"] for r in suspicious_relations) / total_relations
        if total_relations > 0 else 0
    )

    # 构建结果
    result = {
        "suspicious_relations": suspicious_relations,
        "suspicious_subgraphs": suspicious_subgraphs,
        "statistics": {
            "total_relations": total_relations,
            "total_subgraphs": total_subgraphs,
            "avg_correlation": round(avg_correlation, 3)
        }
    }

    # 保存
    output_file = os.path.join(demo_dir, "data_relations.json")
    save_json(output_file, result)

    print(f"\n演示数据已保存到: {output_file}")
    print(f"  - 可疑关系: {total_relations} 条")
    print(f"  - 可疑子图: {total_subgraphs} 个")
    print(f"  - 平均关联度: {result['statistics']['avg_correlation']:.3f}")

if __name__ == "__main__":
    main()
