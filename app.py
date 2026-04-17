# -*- coding: utf-8 -*-
"""
Trace-Eye Demo - APT 威胁检测系统
Flask 主应用入口 - 分步骤执行版本
支持 DEBUG/DEMO 两种模式:
- DEBUG 模式: 使用真实逻辑处理数据
- DEMO 模式: 直接返回预先生成的 JSON 文件
"""

import os
import json
import re
import time
import threading
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_from_directory, Response

# 导入处理模块
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.data_generator import DataGenerator
from modules.event_extractor import EventExtractor
from modules.graph_builder import GraphBuilder
from modules.rule_engine import RuleEngine
from modules.relation_miner import RelationMiner
from modules.threat_detector import ThreatDetector
from modules.attack_chain_builder import AttackChainBuilder
from modules.cache_manager import get_cache_manager

# 创建 Flask 应用
app = Flask(__name__)

# 配置
app.config["JSON_AS_ASCII"] = False
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = True
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB 最大上传

# ==================== 模式配置 ====================
# 通过环境变量 TRACE_EYE_MODE 控制，默认为 "debug"
# DEBUG: 使用真实逻辑处理
# DEMO: 使用预生成数据展示
MODE = os.environ.get("TRACE_EYE_MODE", "demo").lower()
IS_DEMO_MODE = (MODE == "demo")

# 数据目录
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DEMO_DATA_DIR = os.path.join(DATA_DIR, "demo")
LOGS_FILE = os.path.join(DATA_DIR, "data_logs.json")
GRAPH_FILE = os.path.join(DATA_DIR, "data_graph.json")
EVENTS_FILE = os.path.join(DATA_DIR, "data_events.json")
ALERTS_FILE = os.path.join(DATA_DIR, "data_alerts.json")
THREAT_FILE = os.path.join(DATA_DIR, "data_threat.json")
RELATIONS_FILE = os.path.join(DATA_DIR, "data_relations.json")
CHAINS_FILE = os.path.join(DATA_DIR, "data_chains.json")
ANALYSIS_FILE = os.path.join(DATA_DIR, "data_analysis.json")


# ==================== 模式检测函数 ====================

def is_demo_mode():
    """检查是否为 Demo 模式"""
    return IS_DEMO_MODE


def get_demo_file(filename):
    """获取 Demo 模式下的数据文件路径"""
    return os.path.join(DEMO_DATA_DIR, filename)


def ensure_demo_data_exists():
    """确保 Demo 数据文件存在，如果不存在则创建默认数据"""
    if not os.path.exists(DEMO_DATA_DIR):
        os.makedirs(DEMO_DATA_DIR)

    demo_files = {
        "data_events.json": {
            "events": [],
            "statistics": {
                "total_events": 40000,
                "by_type": {"process": 13333, "file": 13333, "network": 13334},
                "by_action": {"execute": 8000, "read": 12000, "write": 6000, "connect": 8000, "open": 6000},
                "by_label": {"benign": 34000, "malicious": 6000}
            }
        },
        "data_graph.json": {
            "nodes": [],
            "edges": [],
            "adjacency": {},
            "statistics": {
                "node_count": 250,
                "edge_count": 750,
                "avg_degree": 6.0,
                "max_degree": 25,
                "density": 0.024
            }
        },
        "data_alerts.json": {
            "alerts": [],
            "statistics": {
                "total_alerts": 156,
                "by_severity": {"high": 45, "medium": 68, "low": 43},
                "by_category": {"file": 42, "process": 58, "network": 56}
            }
        },
        "data_threat.json": {
            "anomaly_detection": {
                "algorithm": "IsolationForest",
                "anomaly_nodes": [],
                "scores": {},
                "threshold": 0.25
            },
            "clustering": {
                "algorithm": "KMeans",
                "n_clusters": 5,
                "labels": {},
                "cluster_stats": {}
            },
            "threat_scores": {},
            "classified_nodes": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "benign": []
            },
            "summary": {
                "total_nodes": 250,
                "by_level": {"critical": 5, "high": 18, "medium": 35, "low": 42, "benign": 150},
                "critical_count": 5,
                "high_count": 18,
                "medium_count": 35,
                "overall_threat_level": "high"
            }
        },
        "data_relations.json": {
            "suspicious_relations": [],
            "suspicious_subgraphs": [],
            "statistics": {
                "total_relations": 45,
                "total_subgraphs": 8,
                "avg_correlation": 0.72
            }
        },
        "data_chains.json": {
            "attack_chains": [],
            "statistics": {
                "total_chains": 8,
                "total_nodes_in_chains": 67,
                "by_attack_type": {
                    "后门通信": 2,
                    "数据窃取": 2,
                    "权限提升": 1,
                    "持久化": 1,
                    "进程注入": 1,
                    "网络通信": 1
                },
                "top_techniques": [
                    ["T1071", 15],
                    ["T1059", 12],
                    ["T1105", 8]
                ],
                "avg_threat_score": 0.68
            }
        },
        "data_analysis.json": {
            "analysis_id": "demo_analysis",
            "analyzed_at": "2025-03-20T10:00:00.000Z",
            "events_statistics": {
                "total_events": 40000
            },
            "graph_statistics": {
                "node_count": 250,
                "edge_count": 750
            },
            "rule_detection": {
                "total_alerts": 156,
                "by_severity": {"high": 45, "medium": 68, "low": 43}
            },
            "threat_detection": {
                "summary": {
                    "overall_threat_level": "high"
                }
            },
            "relation_mining": {
                "total_relations": 45
            },
            "attack_chains": {
                "total_chains": 8
            },
            "overall_assessment": {
                "threat_level": "high",
                "high_risk_nodes": 23,
                "total_alerts": 156
            }
        }
    }

    for filename, default_data in demo_files.items():
        filepath = os.path.join(DEMO_DATA_DIR, filename)
        if not os.path.exists(filepath):
            save_json(filepath, default_data)


def load_json(filepath):
    """加载 JSON 文件"""
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


def save_json(filepath, data):
    """保存 JSON 文件"""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

# 全步状态
system_state = {
    "status": "idle",  # idle, running
    "current_step": "",
    "progress": 0,
    "message": "",
    "steps_completed": [],
    "last_generated": None,
    "mode": MODE.upper()  # 添加模式信息: DEBUG 或 DEMO
}

# ==================== Demo 数据内存缓存 ====================
# 在启动时预加载 demo 数据到内存，避免每次请求都读取大文件

DEMO_DATA_CACHE = {}

def preload_demo_data():
    """预加载所有 demo 数据到内存"""
    global DEMO_DATA_CACHE
    if not IS_DEMO_MODE:
        return

    print("[Demo] 预加载数据到内存...")
    start_time = time.time()

    demo_files = {
        "data_events.json": "events",
        "data_graph.json": "graph",
        "data_alerts.json": "alerts",
        "data_threat.json": "threat",
        "data_relations.json": "relations",
        "data_chains.json": "chains",
        "data_analysis.json": "analysis"
    }

    for filename, key in demo_files.items():
        filepath = get_demo_file(filename)
        try:
            data = load_json(filepath)
            if data:
                DEMO_DATA_CACHE[key] = data
                print(f"[Demo] 加载 {filename}: {len(str(data))} 字符")
        except Exception as e:
            print(f"[Demo] 加载 {filename} 失败: {e}")

    elapsed = time.time() - start_time
    print(f"[Demo] 数据预加载完成，耗时: {elapsed:.2f}秒")

def get_cached_demo_data(key):
    """获取缓存的 demo 数据"""
    return DEMO_DATA_CACHE.get(key)

# Demo 模式下确保数据存在，但不预置步骤为已完成
if IS_DEMO_MODE:
    ensure_demo_data_exists()
    # Demo 模式下步骤需要用户点击"开始演示"后才标记完成
    system_state["demo_mode_ready"] = True

# 步骤定义
STEPS = [
    {"id": "upload", "name": "上传数据", "file": None},
    {"id": "extract", "name": "提取事件", "file": EVENTS_FILE},
    {"id": "graph", "name": "构建关系图", "file": GRAPH_FILE},
    {"id": "rules", "name": "规则检测", "file": ALERTS_FILE},
    {"id": "threat", "name": "威胁检测", "file": THREAT_FILE},
    {"id": "relations", "name": "关系挖掘", "file": RELATIONS_FILE},
    {"id": "chains", "name": "攻击链重建", "file": CHAINS_FILE}
]


# ==================== 辅助函数 ====================

def save_json(filepath, data):
    """保存 JSON 文件"""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_json(filepath):
    """加载 JSON 文件"""
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


def update_state(step, progress, message):
    """更新系统状态"""
    system_state["current_step"] = step
    system_state["progress"] = progress
    system_state["message"] = message


# ==================== 路由处理 ====================

@app.route("/")
def index():
    """首页"""
    return render_template("index.html")


@app.route("/api/status")
def get_status():
    """获取系统状态"""
    # 检查各步骤是否完成
    steps_status = {}
    for step in STEPS:
        steps_status[step["id"]] = {
            "completed": step["id"] in system_state["steps_completed"],
            "has_data": step["file"] and os.path.exists(step["file"])
        }

    response = {
        "status": system_state["status"],
        "current_step": system_state["current_step"],
        "progress": system_state["progress"],
        "message": system_state["message"],
        "steps_status": steps_status,
        "last_generated": system_state["last_generated"],
        "mode": system_state["mode"]  # 添加模式信息
    }

    # Demo 模式下添加特殊标记
    if IS_DEMO_MODE:
        response["demo_mode"] = True
        response["demo_message"] = "当前为演示模式，数据已预加载"

    return jsonify(response)


@app.route("/api/reset", methods=["POST"])
def reset():
    """重置系统"""
    try:
        # 删除数据文件
        for filepath in [LOGS_FILE, GRAPH_FILE, EVENTS_FILE, ALERTS_FILE,
                        THREAT_FILE, RELATIONS_FILE, CHAINS_FILE, ANALYSIS_FILE]:
            if os.path.exists(filepath):
                os.remove(filepath)

        # 清除缓存
        cache_mgr = get_cache_manager()
        cache_mgr.clear_all()

        system_state["status"] = "idle"
        system_state["current_step"] = ""
        system_state["progress"] = 0
        system_state["message"] = "系统已重置"
        system_state["steps_completed"] = []
        system_state["last_generated"] = None

        return jsonify({"success": True, "message": "系统已重置"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/upload", methods=["POST"])
def upload_logs():
    """上传多源日志文件，实际统计日志行数"""
    if system_state["status"] == "running":
        return jsonify({"error": "系统正在运行中"}), 400

    try:
        # 支持单文件和多文件上传
        files_key = "files" if "files" in request.files else "file"

        if files_key not in request.files:
            return jsonify({"error": "未上传文件"}), 400

        files = request.files.getlist(files_key)
        if not files or files[0].filename == "":
            return jsonify({"error": "未选择文件"}), 400

        system_state["status"] = "running"
        update_state("upload", 10, f"正在处理 {len(files)} 个文件...")

        # 导入日志解析器
        from modules.log_parser import LogParser
        parser = LogParser()

        all_events = []
        file_info = []

        # 处理每个上传的文件
        for i, file in enumerate(files):
            filename = file.filename
            update_state("upload", 20 + i * 25, f"读取 {filename}...")

            # 保存到data目录
            file_path = os.path.join(DATA_DIR, filename)
            file.save(file_path)

            # 先统计实际的日志行数
            with open(file_path, 'r', encoding='utf-8') as f:
                line_count = sum(1 for _ in f)

            update_state("upload", 40 + i * 20, f"解析 {filename} ({line_count} 行)...")

            # 检测日志类型
            log_type = detect_log_type(filename, file_path)

            # 解析日志为事件
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                if log_type == "process":
                    events = parser._parse_process_log(content, filename)
                elif log_type == "file":
                    events = parser._parse_file_log(content, filename)
                elif log_type == "network":
                    events = parser._parse_network_log(content, filename)
                else:  # json
                    events = parser._parse_json_log(content, filename)

                all_events.extend(events)
                file_info.append({
                    "filename": filename,
                    "type": log_type,
                    "line_count": line_count,
                    "event_count": len(events)
                })
            except Exception as e:
                return jsonify({"error": f"无法解析文件 {filename}: {str(e)}"}), 400

        # 构建统一的日志数据
        log_data = {
            "meta": {
                "version": "2.0",
                "uploaded_at": datetime.now().isoformat() + "Z",
                "total_events": len(all_events),
                "source": "upload",
                "files": file_info
            },
            "events": all_events
        }

        # 保存到日志文件
        save_json(LOGS_FILE, log_data)

        update_state("upload", 100, "文件上传完成")
        system_state["steps_completed"].append("upload")
        system_state["status"] = "idle"
        system_state["last_generated"] = datetime.now().isoformat()

        # 保存到缓存
        cache_mgr = get_cache_manager()
        cache_mgr.save_step_data("upload", {
            "completed_at": datetime.now().isoformat() + "Z",
            "status": "completed",
            "files": file_info,
            "total_events": len(all_events),
            "log_data_path": LOGS_FILE
        })

        return jsonify({
            "success": True,
            "message": f"成功上传 {len(files)} 个文件",
            "statistics": {
                "total_events": len(all_events),
                "files": file_info
            }
        })

    except Exception as e:
        system_state["status"] = "idle"
        return jsonify({"error": f"上传失败: {str(e)}"}), 500


def detect_log_type(filename: str, filepath: str = None) -> str:
    """根据文件名或内容检测日志类型"""
    name_lower = filename.lower()

    # 根据文件名判断
    if "syslog" in name_lower or "process" in name_lower:
        return "process"
    if "file" in name_lower or "audit" in name_lower:
        return "file"
    if "netflow" in name_lower or "network" in name_lower:
        return "network"
    if filename.endswith(".json"):
        return "json"

    # 如果有文件路径，尝试根据内容判断
    if filepath and os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            first_line = f.readline().strip()

            # syslog格式: Mar 20 10:00:00 hostname process[pid]:
            if re.match(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', first_line):
                return "process"

            # NetFlow格式: timestamp,duration,ip,...
            if ',' in first_line and re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', first_line):
                return "network"

            # 审计日志格式: timestamp|pid|operation
            if '|' in first_line:
                return "file"

    return "json"


@app.route("/api/demo/start", methods=["POST"])
def start_demo_mode():
    """Demo 模式：启动演示（准备数据，标记 upload 完成）"""
    if not IS_DEMO_MODE:
        return jsonify({"error": "当前不是 Demo 模式"}), 400

    try:
        # 清空之前的步骤状态，只标记 upload 为已完成
        system_state["steps_completed"] = ["upload"]
        system_state["demo_started"] = True
        system_state["demo_mode_ready"] = True

        # 确保 demo 数据文件存在
        ensure_demo_data_exists()

        return jsonify({
            "success": True,
            "message": "演示模式已启动，请点击「开始提取」按钮",
            "next_step": "extract"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/generate", methods=["POST"])
def generate_logs():
    """生成多格式测试数据"""
    if system_state["status"] == "running":
        return jsonify({"error": "系统正在运行中"}), 400

    try:
        # 获取参数，支持 JSON body 或默认值
        data = request.get_json(silent=True) or {}
        total_events = data.get("total_events", 40000)  # 默认40000条
        if isinstance(total_events, str):
            total_events = int(total_events)

        system_state["status"] = "running"
        update_state("upload", 10, "开始生成日志数据...")

        # 1. 生成多格式日志文件
        update_state("upload", 30, "生成系统日志...")
        from modules.log_generator import MultiFormatLogGenerator
        generator = MultiFormatLogGenerator()
        generator.generate_all(DATA_DIR, total_events=total_events)

        # 2. 解析生成的日志文件，转换为统一事件格式
        update_state("upload", 60, "解析日志文件...")
        from modules.log_parser import LogParser
        parser = LogParser()

        all_events = []
        log_files = []

        # 解析进程日志
        syslog_path = os.path.join(DATA_DIR, "syslog.log")
        if os.path.exists(syslog_path):
            with open(syslog_path, 'r', encoding='utf-8') as f:
                events = parser._parse_process_log(f.read(), "syslog.log")
            all_events.extend(events)
            log_files.append({"type": "process", "file": "syslog.log", "count": len(events)})

        # 解析文件日志
        audit_path = os.path.join(DATA_DIR, "file_audit.log")
        if os.path.exists(audit_path):
            with open(audit_path, 'r', encoding='utf-8') as f:
                events = parser._parse_file_log(f.read(), "file_audit.log")
            all_events.extend(events)
            log_files.append({"type": "file", "file": "file_audit.log", "count": len(events)})

        # 解析网络日志
        netflow_path = os.path.join(DATA_DIR, "netflow.log")
        if os.path.exists(netflow_path):
            with open(netflow_path, 'r', encoding='utf-8') as f:
                events = parser._parse_network_log(f.read(), "netflow.log")
            all_events.extend(events)
            log_files.append({"type": "network", "file": "netflow.log", "count": len(events)})

        update_state("upload", 80, f"已解析 {len(all_events)} 条事件")

        # 3. 保存到日志文件
        update_state("upload", 90, "保存数据...")
        log_data = {
            "meta": {
                "version": "2.0",
                "generated_at": datetime.now().isoformat() + "Z",
                "total_events": len(all_events),
                "source": "generated",
                "log_files": log_files
            },
            "events": all_events
        }
        save_json(LOGS_FILE, log_data)

        update_state("upload", 100, "数据生成完成")
        system_state["steps_completed"].append("upload")
        system_state["status"] = "idle"
        system_state["last_generated"] = datetime.now().isoformat()

        # 保存到缓存
        file_info = [
            {"filename": f["file"], "type": f["type"], "line_count": f["count"]}
            for f in log_files
        ]
        cache_mgr = get_cache_manager()
        cache_mgr.save_step_data("upload", {
            "completed_at": datetime.now().isoformat() + "Z",
            "status": "completed",
            "files": file_info,
            "total_events": len(all_events),
            "log_data_path": LOGS_FILE,
            "source": "generated"
        })

        return jsonify({
            "success": True,
            "message": "数据生成完成",
            "statistics": {
                "total_events": len(all_events),
                "log_files": log_files
            }
        })

    except Exception as e:
        system_state["status"] = "idle"
        return jsonify({"error": str(e)}), 500


@app.route("/api/step/extract", methods=["POST"])
def step_extract():
    """步骤1: 提取事件"""
    if system_state["status"] == "running":
        return jsonify({"error": "系统正在运行中"}), 400

    # 检查依赖
    if "upload" not in system_state["steps_completed"]:
        return jsonify({"error": "请先上传或生成数据"}), 400

    # Demo 模式：标记完成并返回
    if IS_DEMO_MODE:
        if "extract" not in system_state["steps_completed"]:
            system_state["steps_completed"].append("extract")
        return jsonify({
            "success": True,
            "completed": True,
            "message": "事件提取完成",
            "next_step": "graph",
            "next_step_name": "关系图构建"
        })

    try:
        system_state["status"] = "running"
        update_state("extract", 0, "开始提取事件...")

        # 获取缓存管理器
        cache_mgr = get_cache_manager()
        upload_cache = cache_mgr.get_step_data("upload")

        # 模拟进度（添加延迟以便观察）
        for i in range(1, 6):
            time.sleep(0.3)
            update_state("extract", i * 15, f"提取事件中... {i * 20}%")

        # 执行事件提取
        log_data = load_json(LOGS_FILE)
        extractor = EventExtractor()
        events = extractor.extract_from_logs(log_data)
        statistics = extractor.get_event_statistics(events)

        # 保存结果
        save_json(EVENTS_FILE, {"events": events, "statistics": statistics})

        # 保存到缓存
        cache_mgr.save_step_data("extract", {
            "completed_at": datetime.now().isoformat() + "Z",
            "status": "completed",
            "total_events": len(events),
            "by_type": statistics.get("by_type", {}),
            "events": events[:100],  # 保存前100条事件用于前端显示
            "statistics": statistics,
            "input_from": {
                "step": "upload",
                "total_files": len(upload_cache.get("files", [])) if upload_cache else 0,
                "files": upload_cache.get("files", []) if upload_cache else []
            }
        })

        update_state("extract", 100, "事件提取完成")
        system_state["steps_completed"].append("extract")
        system_state["status"] = "idle"

        return jsonify({
            "success": True,
            "message": "事件提取完成",
            "statistics": statistics
        })

    except Exception as e:
        system_state["status"] = "idle"
        return jsonify({"error": str(e)}), 500


@app.route("/api/step/graph", methods=["POST"])
def step_graph():
    """步骤2: 构建关系图"""
    if system_state["status"] == "running":
        return jsonify({"error": "系统正在运行中"}), 400

    if "extract" not in system_state["steps_completed"]:
        return jsonify({"error": "请先完成事件提取"}), 400

    # Demo 模式：标记完成并返回
    if IS_DEMO_MODE:
        if "graph" not in system_state["steps_completed"]:
            system_state["steps_completed"].append("graph")
        return jsonify({
            "success": True,
            "completed": True,
            "message": "关系图构建完成",
            "next_step": "rules",
            "next_step_name": "规则检测"
        })

    try:
        system_state["status"] = "running"
        update_state("graph", 0, "开始构建关系图...")

        # 获取缓存管理器
        cache_mgr = get_cache_manager()
        extract_cache = cache_mgr.get_step_data("extract")

        # 模拟进度
        for i in range(1, 6):
            time.sleep(0.4)
            update_state("graph", i * 18, f"构建关系图... {i * 18}%")

        # 执行图构建
        events_data = load_json(EVENTS_FILE)
        events = events_data["events"]

        graph_builder = GraphBuilder()
        graph = graph_builder.build_graph(events)

        save_json(GRAPH_FILE, graph)

        # 保存到缓存
        node_count = len(graph.get("nodes", []))
        edge_count = len(graph.get("edges", []))

        cache_mgr.save_step_data("graph", {
            "completed_at": datetime.now().isoformat() + "Z",
            "status": "completed",
            "node_count": node_count,
            "edge_count": edge_count,
            "nodes": graph.get("nodes", [])[:50],  # 保存前50个节点用于前端显示
            "edges": graph.get("edges", [])[:50],  # 保存前50条边用于前端显示
            "statistics": graph.get("statistics", {}),
            "input_from": {
                "step": "extract",
                "total_events": extract_cache.get("total_events", 0) if extract_cache else 0
            }
        })

        update_state("graph", 100, "关系图构建完成")
        system_state["steps_completed"].append("graph")
        system_state["status"] = "idle"

        return jsonify({
            "success": True,
            "message": "关系图构建完成",
            "statistics": graph["statistics"]
        })

    except Exception as e:
        system_state["status"] = "idle"
        return jsonify({"error": str(e)}), 500


@app.route("/api/step/rules", methods=["POST"])
def step_rules():
    """步骤3: 规则检测"""
    if system_state["status"] == "running":
        return jsonify({"error": "系统正在运行中"}), 400

    if "graph" not in system_state["steps_completed"]:
        return jsonify({"error": "请先完成关系图构建"}), 400

    # Demo 模式：标记完成并返回
    if IS_DEMO_MODE:
        if "rules" not in system_state["steps_completed"]:
            system_state["steps_completed"].append("rules")
        return jsonify({
            "success": True,
            "completed": True,
            "message": "规则检测完成",
            "next_step": "threat",
            "next_step_name": "威胁检测"
        })

    try:
        system_state["status"] = "running"
        update_state("rules", 0, "开始规则检测...")

        # 获取缓存管理器
        cache_mgr = get_cache_manager()
        graph_cache = cache_mgr.get_step_data("graph")

        # 模拟进度
        for i in range(1, 6):
            time.sleep(0.5)
            update_state("rules", i * 18, f"执行规则匹配... {i * 18}%")

        # 执行规则检测
        events_data = load_json(EVENTS_FILE)
        events = events_data["events"]

        rule_engine = RuleEngine(max_alerts=500)
        rule_result = rule_engine.evaluate_events(events)

        save_json(ALERTS_FILE, rule_result)

        # 保存到缓存
        alerts = rule_result.get("alerts", [])
        by_severity = rule_result.get("statistics", {}).get("by_severity", {})

        cache_mgr.save_step_data("rules", {
            "completed_at": datetime.now().isoformat() + "Z",
            "status": "completed",
            "total_alerts": len(alerts),
            "by_severity": by_severity,
            "alerts": alerts[:50],  # 保存前50条告警用于前端显示
            "statistics": rule_result.get("statistics", {}),
            "input_from": {
                "step": "graph",
                "node_count": graph_cache.get("node_count", 0) if graph_cache else 0,
                "edge_count": graph_cache.get("edge_count", 0) if graph_cache else 0
            }
        })

        update_state("rules", 100, "规则检测完成")
        system_state["steps_completed"].append("rules")
        system_state["status"] = "idle"

        return jsonify({
            "success": True,
            "message": "规则检测完成",
            "statistics": rule_result["statistics"]
        })

    except Exception as e:
        system_state["status"] = "idle"
        return jsonify({"error": str(e)}), 500


@app.route("/api/step/threat", methods=["POST"])
def step_threat():
    """步骤4: 威胁检测"""
    if system_state["status"] == "running":
        return jsonify({"error": "系统正在运行中"}), 400

    if "rules" not in system_state["steps_completed"]:
        return jsonify({"error": "请先完成规则检测"}), 400

    # Demo 模式：标记完成并返回
    if IS_DEMO_MODE:
        if "threat" not in system_state["steps_completed"]:
            system_state["steps_completed"].append("threat")
        return jsonify({
            "success": True,
            "completed": True,
            "message": "威胁检测完成",
            "next_step": "relations",
            "next_step_name": "关系挖掘"
        })

    try:
        system_state["status"] = "running"
        update_state("threat", 0, "开始威胁检测...")

        # 获取缓存管理器
        cache_mgr = get_cache_manager()
        rules_cache = cache_mgr.get_step_data("rules")

        # 模拟进度
        stages = [
            (10, "提取节点特征..."),
            (30, "执行异常检测..."),
            (50, "执行行为聚类..."),
            (70, "计算威胁评分..."),
            (90, "分类节点...")
        ]

        for progress, msg in stages:
            time.sleep(0.6)
            update_state("threat", progress, msg)

        # 执行威胁检测
        graph = load_json(GRAPH_FILE)
        alerts_data = load_json(ALERTS_FILE)
        alerts = alerts_data.get("alerts", [])

        threat_detector = ThreatDetector()
        threat_result = threat_detector.detect(graph, alerts)

        save_json(THREAT_FILE, threat_result)

        # 保存到缓存
        summary = threat_result.get("summary", {})
        anomaly_nodes = threat_result.get("anomaly_detection", {}).get("anomaly_nodes", [])
        classified_nodes = threat_result.get("classified_nodes", {})

        cache_mgr.save_step_data("threat", {
            "completed_at": datetime.now().isoformat() + "Z",
            "status": "completed",
            "overall_threat_level": summary.get("overall_threat_level", "unknown"),
            "anomaly_count": len(anomaly_nodes),
            "anomaly_nodes": anomaly_nodes[:20],  # 保存前20个异常节点
            "classified_nodes": classified_nodes,
            "summary": summary,
            "input_from": {
                "step": "rules",
                "total_alerts": rules_cache.get("total_alerts", 0) if rules_cache else 0
            }
        })

        update_state("threat", 100, "威胁检测完成")
        system_state["steps_completed"].append("threat")
        system_state["status"] = "idle"

        return jsonify({
            "success": True,
            "message": "威胁检测完成",
            "summary": threat_result["summary"]
        })

    except Exception as e:
        system_state["status"] = "idle"
        return jsonify({"error": str(e)}), 500


@app.route("/api/step/relations", methods=["POST"])
def step_relations():
    """步骤5: 关系挖掘"""
    if system_state["status"] == "running":
        return jsonify({"error": "系统正在运行中"}), 400

    if "threat" not in system_state["steps_completed"]:
        return jsonify({"error": "请先完成威胁检测"}), 400

    # Demo 模式：标记完成并返回
    if IS_DEMO_MODE:
        if "relations" not in system_state["steps_completed"]:
            system_state["steps_completed"].append("relations")
        return jsonify({
            "success": True,
            "completed": True,
            "message": "关系挖掘完成",
            "next_step": "chains",
            "next_step_name": "攻击链重建"
        })

    try:
        system_state["status"] = "running"
        update_state("relations", 0, "开始挖掘可疑关系...")

        # 获取缓存管理器
        cache_mgr = get_cache_manager()
        threat_cache = cache_mgr.get_step_data("threat")

        # 模拟进度
        for i in range(1, 6):
            time.sleep(0.5)
            update_state("relations", i * 18, f"挖掘可疑关系... {i * 18}%")

        # 执行关系挖掘
        graph = load_json(GRAPH_FILE)
        threat_data = load_json(THREAT_FILE)
        anomaly_nodes = threat_data["anomaly_detection"]["anomaly_nodes"]

        relation_miner = RelationMiner(graph)
        relation_result = relation_miner.mine_suspicious_relations(anomaly_nodes)

        save_json(RELATIONS_FILE, relation_result)

        # 保存到缓存
        suspicious_relations = relation_result.get("suspicious_relations", [])
        suspicious_subgraphs = relation_result.get("suspicious_subgraphs", [])

        cache_mgr.save_step_data("relations", {
            "completed_at": datetime.now().isoformat() + "Z",
            "status": "completed",
            "relation_count": len(suspicious_relations),
            "subgraph_count": len(suspicious_subgraphs),
            "suspicious_relations": suspicious_relations[:30],  # 保存前30条关系
            "suspicious_subgraphs": suspicious_subgraphs[:10],  # 保存前10个子图
            "statistics": relation_result.get("statistics", {}),
            "input_from": {
                "step": "threat",
                "anomaly_count": threat_cache.get("anomaly_count", 0) if threat_cache else 0
            }
        })

        update_state("relations", 100, "关系挖掘完成")
        system_state["steps_completed"].append("relations")
        system_state["status"] = "idle"

        return jsonify({
            "success": True,
            "message": "关系挖掘完成",
            "statistics": relation_result["statistics"]
        })

    except Exception as e:
        system_state["status"] = "idle"
        return jsonify({"error": str(e)}), 500


@app.route("/api/step/chains", methods=["POST"])
def step_chains():
    """步骤6: 攻击链重建"""
    if system_state["status"] == "running":
        return jsonify({"error": "系统正在运行中"}), 400

    if "relations" not in system_state["steps_completed"]:
        return jsonify({"error": "请先完成关系挖掘"}), 400

    # Demo 模式：标记完成并返回
    if IS_DEMO_MODE:
        if "chains" not in system_state["steps_completed"]:
            system_state["steps_completed"].append("chains")
        return jsonify({
            "success": True,
            "completed": True,
            "message": "攻击链重建完成",
            "next_step": "ai",
            "next_step_name": "AI 智能分析"
        })

    try:
        system_state["status"] = "running"
        update_state("chains", 0, "开始重建攻击链...")

        # 获取缓存管理器
        cache_mgr = get_cache_manager()
        relations_cache = cache_mgr.get_step_data("relations")

        # 模拟进度
        stages = [
            (15, "识别告警节点..."),
            (35, "提取节点特征..."),
            (55, "执行聚类分析..."),
            (75, "构建攻击链..."),
            (90, "生成攻击报告...")
        ]

        for progress, msg in stages:
            time.sleep(0.6)
            update_state("chains", progress, msg)

        # 执行攻击链重建
        graph = load_json(GRAPH_FILE)
        alerts_data = load_json(ALERTS_FILE)
        alerts = alerts_data.get("alerts", [])
        threat_data = load_json(THREAT_FILE)
        threat_scores = threat_data["threat_scores"]

        chain_builder = AttackChainBuilder()
        chain_result = chain_builder.build_attack_chains(graph, alerts, threat_scores)

        save_json(CHAINS_FILE, chain_result)

        # 保存到缓存
        attack_chains = chain_result.get("attack_chains", [])

        cache_mgr.save_step_data("chains", {
            "completed_at": datetime.now().isoformat() + "Z",
            "status": "completed",
            "chain_count": len(attack_chains),
            "attack_chains": attack_chains[:10],  # 保存前10条攻击链
            "statistics": chain_result.get("statistics", {}),
            "input_from": {
                "step": "relations",
                "relation_count": relations_cache.get("relation_count", 0) if relations_cache else 0
            }
        })

        # 生成最终分析报告
        analysis_result = {
            "analysis_id": f"analysis_{int(time.time())}",
            "analyzed_at": datetime.now().isoformat(),
            "events_statistics": load_json(EVENTS_FILE)["statistics"],
            "graph_statistics": load_json(GRAPH_FILE)["statistics"],
            "rule_detection": {
                "total_alerts": load_json(ALERTS_FILE)["statistics"]["total_alerts"],
                "by_severity": load_json(ALERTS_FILE)["statistics"]["by_severity"]
            },
            "threat_detection": {
                "summary": load_json(THREAT_FILE)["summary"]
            },
            "relation_mining": {
                "total_relations": load_json(RELATIONS_FILE)["statistics"]["total_relations"]
            },
            "attack_chains": {
                "total_chains": chain_result["statistics"]["total_chains"],
                "by_attack_type": chain_result["statistics"]["by_attack_type"]
            },
            "overall_assessment": {
                "threat_level": load_json(THREAT_FILE)["summary"]["overall_threat_level"],
                "high_risk_nodes": len(load_json(THREAT_FILE)["classified_nodes"].get("high", [])) +
                                  len(load_json(THREAT_FILE)["classified_nodes"].get("critical", [])),
                "total_alerts": load_json(ALERTS_FILE)["statistics"]["total_alerts"]
            }
        }

        save_json(ANALYSIS_FILE, analysis_result)

        update_state("chains", 100, "攻击链重建完成")
        system_state["steps_completed"].append("chains")
        system_state["status"] = "idle"

        return jsonify({
            "success": True,
            "message": "攻击链重建完成",
            "statistics": chain_result["statistics"]
        })

    except Exception as e:
        system_state["status"] = "idle"
        return jsonify({"error": str(e)}), 500


# ==================== 数据获取接口 ====================

@app.route("/api/events")
def get_events():
    """获取事件列表"""
    # Demo 模式：使用预生成数据
    if IS_DEMO_MODE:
        events_data = get_cached_demo_data("events")
    else:
        events_data = load_json(EVENTS_FILE)

    if not events_data:
        return jsonify({"events": [], "total": 0})

    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)

    events = events_data.get("events", [])
    total = len(events)
    events_page = events[offset:offset + limit]

    return jsonify({
        "total": total,
        "offset": offset,
        "limit": limit,
        "events": events_page
    })


@app.route("/api/graph")
def get_graph():
    """获取关系图数据"""
    # Demo 模式：使用预生成数据
    if IS_DEMO_MODE:
        graph_data = get_cached_demo_data("graph")
    else:
        graph_data = load_json(GRAPH_FILE)

    if not graph_data:
        return jsonify({"nodes": [], "edges": []})

    return jsonify(graph_data)


@app.route("/api/alerts")
def get_alerts():
    """获取告警列表（支持分页）"""
    # Demo 模式：使用预生成数据
    if IS_DEMO_MODE:
        alerts_data = get_cached_demo_data("alerts")
    else:
        alerts_data = load_json(ALERTS_FILE)

    if not alerts_data:
        return jsonify({"alerts": [], "total": 0, "page": 1, "page_size": 20, "total_pages": 0})

    page = request.args.get("page", 1, type=int)
    page_size = request.args.get("page_size", 20, type=int)

    alerts = alerts_data.get("alerts", [])
    total = len(alerts)

    # 计算分页
    total_pages = (total + page_size - 1) // page_size if total > 0 else 1
    page = max(1, min(page, total_pages))  # 确保页码有效

    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    alerts_page = alerts[start_idx:end_idx]

    return jsonify({
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "alerts": alerts_page
    })


@app.route("/api/threat")
def get_threat():
    """获取威胁检测结果"""
    # Demo 模式：使用预生成数据
    if IS_DEMO_MODE:
        threat_data = get_cached_demo_data("threat")
    else:
        threat_data = load_json(THREAT_FILE)

    if not threat_data:
        return jsonify({"error": "威胁检测结果不存在"}), 404

    return jsonify(threat_data)


@app.route("/api/relations")
def get_relations():
    """获取关系挖掘结果"""
    # Demo 模式：使用预生成数据
    if IS_DEMO_MODE:
        relations_data = get_cached_demo_data("relations")
    else:
        relations_data = load_json(RELATIONS_FILE)

    if not relations_data:
        return jsonify({"error": "关系挖掘结果不存在"}), 404

    return jsonify(relations_data)


@app.route("/api/chains")
def get_chains():
    """获取攻击链结果"""
    # Demo 模式：使用预生成数据
    if IS_DEMO_MODE:
        chains_data = get_cached_demo_data("chains")
    else:
        chains_data = load_json(CHAINS_FILE)

    if not chains_data:
        return jsonify({"error": "攻击链结果不存在"}), 404

    return jsonify(chains_data)


@app.route("/api/analysis")
def get_analysis():
    """获取完整分析结果"""
    # Demo 模式：使用预生成数据
    if IS_DEMO_MODE:
        analysis_data = get_cached_demo_data("analysis")
    else:
        analysis_data = load_json(ANALYSIS_FILE)

    if not analysis_data:
        return jsonify({"error": "分析结果不存在"}), 404

    return jsonify(analysis_data)


@app.route("/api/scenarios")
def get_scenarios():
    """获取攻击场景列表和统计数据"""
    # Demo 模式：返回预定义场景
    if IS_DEMO_MODE:
        scenarios = [
            {
                "scenario": {
                    "id": "scen_001",
                    "name": "Firefox后门植入",
                    "type": "backdoor",
                    "description": "通过Firefox漏洞下载恶意文件并执行后门",
                    "techniques": ["T1190", "T1059", "T1071"]
                },
                "event_count": 45
            },
            {
                "scenario": {
                    "id": "scen_002",
                    "name": "供应链攻击",
                    "type": "supply_chain",
                    "description": "通过被篡改的软件包植入恶意代码",
                    "techniques": ["T1195", "T1059"]
                },
                "event_count": 38
            },
            {
                "scenario": {
                    "id": "scen_003",
                    "name": "权限提升",
                    "type": "privilege_escalation",
                    "description": "利用sudo提权漏洞获取root权限",
                    "techniques": ["T1068"]
                },
                "event_count": 32
            },
            {
                "scenario": {
                    "id": "scen_004",
                    "name": "数据窃取",
                    "type": "data_exfiltration",
                    "description": "扫描敏感文件并打包外传",
                    "techniques": ["T1005", "T1041"]
                },
                "event_count": 28
            },
            {
                "scenario": {
                    "id": "scen_005",
                    "name": "反向Shell",
                    "type": "reverse_shell",
                    "description": "建立反向Shell连接",
                    "techniques": ["T1059"]
                },
                "event_count": 25
            }
        ]
        statistics = {
            "total_events": 40000,
            "attack_events": 6000,
            "benign_events": 34000,
            "entity_count": 250,
            "scenario_count": 15
        }
        return jsonify({"scenarios": scenarios, "statistics": statistics})

    # Debug 模式：从实际数据读取
    log_data = load_json(LOGS_FILE)
    if not log_data:
        return jsonify({"scenarios": [], "statistics": {}})

    scenarios = log_data.get("scenarios", [])
    meta = log_data.get("meta", {})
    events = log_data.get("events", [])

    # 从meta获取统计，如果没有则从events计算
    total_events = meta.get("total_events", len(events))
    attack_events = meta.get("attack_events", 0)
    benign_events = meta.get("benign_events", 0)

    # 如果meta中没有attack/benign统计，从events中计算
    if attack_events == 0 and benign_events == 0 and events:
        attack_count = sum(1 for e in events if e.get("label") == "malicious")
        benign_count = sum(1 for e in events if e.get("label") == "benign")
        attack_events = attack_count
        benign_events = benign_count

    statistics = {
        "total_events": total_events,
        "attack_events": attack_events,
        "benign_events": benign_events,
        "entity_count": meta.get("entity_count", 0),
        "scenario_count": len(scenarios)
    }
    return jsonify({"scenarios": scenarios, "statistics": statistics})


@app.route("/api/logs/info")
def get_logs_info():
    """获取已上传/生成的日志文件信息"""
    # Demo 模式：返回预生成的演示文件信息
    if IS_DEMO_MODE and system_state.get("demo_started"):
        events_data = get_cached_demo_data("events")
        stats = events_data.get("statistics", {}) if events_data else {}
        return jsonify({
            "files": [
                {"name": "syslog.log", "type": "process", "lines": stats.get("by_type", {}).get("process", 13333)},
                {"name": "file_audit.log", "type": "file", "lines": stats.get("by_type", {}).get("file", 13333)},
                {"name": "netflow.log", "type": "network", "lines": stats.get("by_type", {}).get("network", 13334)}
            ],
            "total_lines": stats.get("total_events", 40000),
            "demo_mode": True
        })

    log_data = load_json(LOGS_FILE)
    if not log_data:
        return jsonify({"files": []})

    files_info = []

    # 检查是否有log_files信息（上传或生成时记录的）
    log_files = log_data.get("meta", {}).get("log_files", [])

    if log_files:
        # 有记录的文件信息
        for log_file in log_files:
            files_info.append({
                "filename": log_file.get("file", "unknown"),
                "type": log_file.get("type", "unknown"),
                "line_count": log_file.get("count", 0)
            })
    else:
        # 没有记录，从实际文件推断
        syslog_path = os.path.join(DATA_DIR, "syslog.log")
        audit_path = os.path.join(DATA_DIR, "file_audit.log")
        netflow_path = os.path.join(DATA_DIR, "netflow.log")

        if os.path.exists(syslog_path):
            with open(syslog_path, 'r') as f:
                files_info.append({
                    "filename": "syslog.log",
                    "type": "process",
                    "line_count": sum(1 for _ in f)
                })

        if os.path.exists(audit_path):
            with open(audit_path, 'r') as f:
                files_info.append({
                    "filename": "file_audit.log",
                    "type": "file",
                    "line_count": sum(1 for _ in f)
                })

        if os.path.exists(netflow_path):
            with open(netflow_path, 'r') as f:
                files_info.append({
                    "filename": "netflow.log",
                    "type": "network",
                    "line_count": sum(1 for _ in f)
                })

    return jsonify({"files": files_info})


# ==================== 缓存数据获取接口 ====================

@app.route("/api/cache/<step>")
def get_step_cache(step):
    """获取指定步骤的缓存数据（用于显示输入/输出）"""
    if step not in ["upload", "extract", "graph", "rules", "threat", "relations", "chains"]:
        return jsonify({"error": "无效的步骤名称"}), 400

    # Demo 模式：从内存缓存读取（预加载）
    if IS_DEMO_MODE:
        demo_key_map = {
            "upload": "events",
            "extract": "events",
            "graph": "graph",
            "rules": "alerts",
            "threat": "threat",
            "relations": "relations",
            "chains": "chains"
        }

        if step in demo_key_map:
            demo_data = get_cached_demo_data(demo_key_map[step])
            if demo_data:
                # 根据不同步骤返回适当的数据格式
                if step == "rules":
                    summary = {
                        "step": step,
                        "total_alerts": demo_data.get("statistics", {}).get("total_alerts", len(demo_data.get("alerts", []))),
                        "by_severity": demo_data.get("statistics", {}).get("by_severity", {})
                    }
                    return jsonify({
                        "data": demo_data,
                        "summary": summary
                    })
                elif step == "extract":
                    summary = {
                        "step": step,
                        "total_events": demo_data.get("statistics", {}).get("total_events", 0),
                        "by_type": demo_data.get("statistics", {}).get("by_type", {}),
                        "by_action": demo_data.get("statistics", {}).get("by_action", {}),
                        "by_label": demo_data.get("statistics", {}).get("by_label", {})
                    }
                    return jsonify({
                        "data": demo_data,
                        "summary": summary
                    })
                elif step == "graph":
                    summary = {
                        "step": step,
                        "nodes": len(demo_data.get("nodes", [])),
                        "edges": len(demo_data.get("edges", [])),
                        "node_count": len(demo_data.get("nodes", [])),
                        "edge_count": len(demo_data.get("edges", []))
                    }
                    return jsonify({
                        "data": demo_data,
                        "summary": summary
                    })
                elif step == "threat":
                    summary = demo_data.get("summary", {})
                    return jsonify({
                        "data": demo_data,
                        "summary": summary
                    })
                else:
                    return jsonify({
                        "data": demo_data,
                        "summary": {"step": step}
                    })

    cache_mgr = get_cache_manager()
    step_data = cache_mgr.get_step_data(step)

    if not step_data:
        return jsonify({"error": f"步骤 {step} 的缓存数据不存在"}), 404

    # 同时获取该步骤的摘要信息
    summary = cache_mgr.get_step_summary(step)

    return jsonify({
        "data": step_data,
        "summary": summary
    })


@app.route("/api/cache/all")
def get_all_cache():
    """获取所有步骤的缓存状态"""
    cache_mgr = get_cache_manager()
    all_status = cache_mgr.get_all_steps_status()

    return jsonify(all_status)


# ==================== 数据下载接口 ====================

# ==================== LLM AI 分析接口 ====================

@app.route("/api/llm/status")
def llm_status():
    """获取 LLM 服务状态"""
    from modules.llm_analyzer import get_llm_analyzer
    analyzer = get_llm_analyzer()

    return jsonify({
        "available": analyzer.is_available(),
        "configured": bool(analyzer.api_key),
        "model": analyzer.model,
        "mock_mode": analyzer.use_mock,  # 添加模拟模式标识
        "mode": "mock" if analyzer.use_mock else "real"
    })


@app.route("/api/llm/analyze", methods=["POST"])
def llm_analyze():
    """执行 LLM 告警分析"""
    if system_state["status"] == "running":
        return jsonify({"error": "系统正在运行中"}), 400

    # 检查规则检测是否完成
    if "rules" not in system_state["steps_completed"]:
        return jsonify({"error": "请先完成规则检测"}), 400

    try:
        system_state["status"] = "running"

        # 导入组件
        import asyncio
        from modules.llm_analyzer import get_llm_analyzer

        analyzer = get_llm_analyzer()

        if not analyzer.is_available():
            system_state["status"] = "idle"
            return jsonify({
                "error": "LLM 服务不可用",
                "message": "请配置 OPENAI_API_KEY 环境变量",
                "llm_available": False
            }), 503

        # 获取数据
        if IS_DEMO_MODE:
            alerts_data = get_cached_demo_data("alerts")
            graph_data = get_cached_demo_data("graph")
            events_data = get_cached_demo_data("events")
        else:
            alerts_data = load_json(ALERTS_FILE)
            graph_data = load_json(GRAPH_FILE)
            events_data = load_json(EVENTS_FILE)

        alerts = alerts_data.get("alerts", []) if alerts_data else []
        graph = graph_data or {}
        events = events_data.get("events", []) if events_data else []

        # 运行异步分析
        async def run_analysis():
            progress_updates = []

            async def progress_cb(value, message):
                progress_updates.append({"value": value, "message": message})

            result = await analyzer.analyze_alerts(
                alerts[:100],  # 限制输入数量
                graph,
                events[:500],
                progress_cb
            )
            return result, progress_updates

        result, progress_updates = asyncio.run(run_analysis())

        # 保存分析结果
        if IS_DEMO_MODE:
            llm_result_file = os.path.join(DEMO_DATA_DIR, "data_llm_analysis.json")
        else:
            llm_result_file = os.path.join(DATA_DIR, "data_llm_analysis.json")
        save_json(llm_result_file, result)

        system_state["status"] = "idle"

        return jsonify({
            "success": True,
            "message": "AI 分析完成",
            "result": result,
            "progress": progress_updates
        })

    except Exception as e:
        system_state["status"] = "idle"
        import traceback
        traceback.print_exc()
        return jsonify({
            "error": str(e),
            "message": f"AI 分析失败: {str(e)}"
        }), 500


@app.route("/api/llm/result")
def get_llm_result():
    """获取 LLM 分析结果"""
    llm_file = os.path.join(DATA_DIR, "data_llm_analysis.json")

    if os.path.exists(llm_file):
        return jsonify(load_json(llm_file))

    return jsonify({
        "error": "LLM 分析结果不存在",
        "message": "请先执行 AI 分析",
        "analyzed": False
    }), 404


# ==================== 数据下载接口 ====================

@app.route("/api/download/<file_type>")
def download_file(file_type):
    """下载指定类型的处理结果文件"""
    file_map = {
        "logs": (LOGS_FILE, "data_logs.json", "原始日志数据"),
        "events": (EVENTS_FILE, "data_events.json", "事件提取结果"),
        "graph": (GRAPH_FILE, "data_graph.json", "关系图数据"),
        "alerts": (ALERTS_FILE, "data_alerts.json", "规则检测告警"),
        "threat": (THREAT_FILE, "data_threat.json", "威胁检测结果"),
        "relations": (RELATIONS_FILE, "data_relations.json", "关系挖掘结果"),
        "chains": (CHAINS_FILE, "data_chains.json", "攻击链重建结果"),
        "analysis": (ANALYSIS_FILE, "data_analysis.json", "最终分析报告")
    }

    if file_type not in file_map:
        return jsonify({"error": "无效的文件类型"}), 400

    filepath, filename, display_name = file_map[file_type]

    if not os.path.exists(filepath):
        return jsonify({"error": f"{display_name}不存在，请先完成相应步骤"}), 404

    def generate():
        with open(filepath, 'r', encoding='utf-8') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                yield chunk

    return Response(
        generate(),
        mimetype='application/json',
        headers={
            'Content-Disposition': f'attachment; filename="{filename}"',
            'Content-Type': 'application/json; charset=utf-8'
        }
    )


@app.route("/api/files")
def list_files():
    """获取所有数据文件的状态"""
    files_info = {}
    file_map = {
        "logs": (LOGS_FILE, "原始日志数据"),
        "events": (EVENTS_FILE, "事件提取结果"),
        "graph": (GRAPH_FILE, "关系图数据"),
        "alerts": (ALERTS_FILE, "规则检测告警"),
        "threat": (THREAT_FILE, "威胁检测结果"),
        "relations": (RELATIONS_FILE, "关系挖掘结果"),
        "chains": (CHAINS_FILE, "攻击链重建结果"),
        "analysis": (ANALYSIS_FILE, "最终分析报告")
    }

    for key, (filepath, name) in file_map.items():
        exists = os.path.exists(filepath)
        size = 0
        modified = None
        if exists:
            size = os.path.getsize(filepath)
            modified = datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()

        files_info[key] = {
            "name": name,
            "exists": exists,
            "size": size,
            "size_human": f"{size / 1024:.1f} KB" if size < 1024*1024 else f"{size / (1024*1024):.1f} MB",
            "modified": modified,
            "download_url": f"/api/download/{key}" if exists else None
        }

    return jsonify(files_info)


# ==================== 错误处理 ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "接口不存在"}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "服务器内部错误"}), 500


# ==================== 主函数 ====================

if __name__ == "__main__":
    mode_display = "DEMO (演示模式)" if IS_DEMO_MODE else "DEBUG (调试模式 - 真实处理)"
    mode_info = "数据已预加载，直接展示" if IS_DEMO_MODE else "使用真实算法处理数据"

    print(f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║          Trace-Eye Demo - APT 威胁检测系统                  ║
    ║                                                            ║
    ║  当前模式: {mode_display:30} ║
    ║  {mode_info:40} ║
    ║                                                            ║
    ║  环境变量: TRACE_EYE_MODE={'demo' if IS_DEMO_MODE else 'debug'}     ║
    ║  访问地址: http://localhost:5000                            ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

    # Demo 模式下确保数据目录存在，并预加载数据到内存
    if IS_DEMO_MODE:
        ensure_demo_data_exists()
        preload_demo_data()  # 预加载数据到内存
        print("[OK] Demo data ready")

    app.run(host="0.0.0.0", port=5000, debug=True)
