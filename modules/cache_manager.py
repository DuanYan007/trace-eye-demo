# -*- coding: utf-8 -*-
"""
步骤数据缓存管理
管理各个处理步骤之间的数据传递和缓存
"""

import os
import json
from datetime import datetime
from typing import Dict, Any, Optional


class StepCacheManager:
    """步骤缓存管理器"""

    def __init__(self, cache_dir: str = None):
        if cache_dir is None:
            cache_dir = os.path.join(os.path.dirname(__file__), "..", "cache")

        self.cache_dir = cache_dir
        self.step_data_file = os.path.join(cache_dir, "step_data.json")
        self.ensure_cache_dirs()

    def ensure_cache_dirs(self):
        """确保缓存目录存在"""
        steps = ["upload", "extract", "graph", "rules", "threat", "relations", "chains"]
        for step in steps:
            os.makedirs(os.path.join(self.cache_dir, step), exist_ok=True)

    def save_step_data(self, step: str, data: Dict[str, Any]) -> bool:
        """
        保存步骤处理后的数据到缓存

        Args:
            step: 步骤名称 (upload, extract, graph, etc.)
            data: 要缓存的数据

        Returns:
            bool: 是否保存成功
        """
        try:
            # 保存到步骤专属目录
            step_file = os.path.join(self.cache_dir, step, "result.json")
            with open(step_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            # 更新步骤数据索引
            self._update_step_index(step, data)

            return True
        except Exception as e:
            print(f"保存缓存失败 ({step}): {e}")
            return False

    def get_step_data(self, step: str) -> Optional[Dict[str, Any]]:
        """
        获取步骤缓存的数据

        Args:
            step: 步骤名称

        Returns:
            Dict or None: 缓存的数据，如果不存在返回None
        """
        try:
            step_file = os.path.join(self.cache_dir, step, "result.json")
            if os.path.exists(step_file):
                with open(step_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            return None
        except Exception as e:
            print(f"读取缓存失败 ({step}): {e}")
            return None

    def get_step_summary(self, step: str) -> Optional[Dict[str, Any]]:
        """
        获取步骤摘要信息（用于页面显示）

        Args:
            step: 步骤名称

        Returns:
            Dict or None: 摘要信息
        """
        data = self.get_step_data(step)
        if not data:
            return None

        # 提取摘要信息
        summary = {
            "step": step,
            "completed_at": data.get("completed_at"),
            "status": data.get("status", "completed")
        }

        # 根据不同步骤提取不同的摘要字段
        if step == "upload":
            summary["files"] = data.get("files", [])
            summary["total_lines"] = sum(f.get("line_count", 0) for f in data.get("files", []))

        elif step == "extract":
            summary["total_events"] = data.get("total_events", 0)
            summary["by_type"] = data.get("by_type", {})

        elif step == "graph":
            summary["nodes"] = data.get("node_count", 0)
            summary["edges"] = data.get("edge_count", 0)

        elif step == "rules":
            summary["total_alerts"] = data.get("total_alerts", 0)
            summary["by_severity"] = data.get("by_severity", {})

        elif step == "threat":
            summary["threat_level"] = data.get("overall_threat_level", "unknown")
            summary["anomalies"] = data.get("anomaly_count", 0)

        elif step == "relations":
            summary["relations"] = data.get("relation_count", 0)

        elif step == "chains":
            summary["chains"] = data.get("chain_count", 0)

        return summary

    def _update_step_index(self, step: str, data: Dict[str, Any]):
        """更新步骤索引"""
        try:
            index = self._load_step_index()
            index[step] = {
                "completed_at": datetime.now().isoformat() + "Z",
                "has_data": True,
                "summary": self._extract_summary(step, data)
            }
            self._save_step_index(index)
        except Exception as e:
            print(f"更新索引失败: {e}")

    def _load_step_index(self) -> Dict[str, Dict]:
        """加载步骤索引"""
        try:
            if os.path.exists(self.step_data_file):
                with open(self.step_data_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except:
            pass
        return {}

    def _save_step_index(self, index: Dict):
        """保存步骤索引"""
        with open(self.step_data_file, 'w', encoding='utf-8') as f:
            json.dump(index, f, indent=2, ensure_ascii=False)

    def _extract_summary(self, step: str, data: Dict[str, Any]) -> Dict:
        """从数据中提取摘要信息"""
        summary = {"step": step}

        if step == "upload":
            files = data.get("files", [])
            summary.update({
                "file_count": len(files),
                "total_lines": sum(f.get("line_count", 0) for f in files),
                "files": [{"name": f["filename"], "type": f["type"], "lines": f["line_count"]} for f in files]
            })

        elif step == "extract":
            events = data.get("events", [])
            by_type = {}
            for e in events:
                t = e.get("log_type", "unknown")
                by_type[t] = by_type.get(t, 0) + 1
            summary.update({
                "total_events": len(events),
                "by_type": by_type
            })

        elif step == "graph":
            summary.update({
                "node_count": data.get("nodes", len(data.get("nodes", []))),
                "edge_count": data.get("edges", len(data.get("edges", []))),
                "density": data.get("density", 0)
            })

        elif step == "rules":
            alerts = data.get("alerts", [])
            by_severity = {}
            for a in alerts:
                s = a.get("rule", {}).get("severity", "low")
                by_severity[s] = by_severity.get(s, 0) + 1
            summary.update({
                "total_alerts": len(alerts),
                "by_severity": by_severity
            })

        elif step == "threat":
            classified = data.get("classified_nodes", {})
            original_summary = data.get("summary", {})
            summary.update({
                "total_nodes": original_summary.get("total_nodes", 0),
                "by_level": original_summary.get("by_level", {}),
                "critical_count": original_summary.get("critical_count", len(classified.get("critical", []))),
                "high_count": original_summary.get("high_count", len(classified.get("high", []))),
                "medium_count": original_summary.get("medium_count", len(classified.get("medium", []))),
                "anomaly_count": len(data.get("anomaly_nodes", [])),
                "overall_threat_level": original_summary.get("overall_threat_level", "unknown")
            })

        elif step == "relations":
            relations = data.get("suspicious_relations", [])
            summary.update({
                "relation_count": len(relations),
                "subgraph_count": len(data.get("suspicious_subgraphs", []))
            })

        elif step == "chains":
            chains = data.get("attack_chains", [])
            summary.update({
                "chain_count": len(chains)
            })

        return summary

    def clear_step(self, step: str) -> bool:
        """清除指定步骤的缓存"""
        try:
            step_file = os.path.join(self.cache_dir, step, "result.json")
            if os.path.exists(step_file):
                os.remove(step_file)

            index = self._load_step_index()
            if step in index:
                index[step] = {"completed_at": None, "has_data": False}
                self._save_step_index(index)

            return True
        except Exception as e:
            print(f"清除缓存失败 ({step}): {e}")
            return False

    def clear_all(self) -> bool:
        """清除所有缓存"""
        try:
            import shutil
            if os.path.exists(self.cache_dir):
                shutil.rmtree(self.cache_dir)
            self.ensure_cache_dirs()
            return True
        except Exception as e:
            print(f"清除所有缓存失败: {e}")
            return False

    def get_all_steps_status(self) -> Dict[str, Dict]:
        """获取所有步骤的状态"""
        return self._load_step_index()


# 全局缓存管理器实例
_cache_manager = None


def get_cache_manager() -> StepCacheManager:
    """获取全局缓存管理器实例"""
    global _cache_manager
    if _cache_manager is None:
        # 获取项目根目录
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cache_dir = os.path.join(project_root, "cache")
        _cache_manager = StepCacheManager(cache_dir)
    return _cache_manager
