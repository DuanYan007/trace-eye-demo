# -*- coding: utf-8 -*-
"""
事件提取模块
将原始日志转换为统一格式的事件信息
"""

import json
from typing import List, Dict, Any
from datetime import datetime


class EventExtractor:
    """事件提取器 - 将多源日志转换为统一事件格式"""

    def __init__(self):
        # 统一事件格式的字段定义
        self.event_schema = {
            "event_id": str,
            "timestamp": str,
            "subject": dict,  # 主体实体
            "object": dict,   # 客体实体（可选）
            "action": str,    # 动作类型
            "attributes": dict,  # 额外属性
            "log_type": str,  # 原始日志类型
            "label": str,     # 标签（用于验证）
            "scenario_id": str,  # 关联场景（可选）
            "scenario_name": str  # 场景名称（可选）
        }

        # 支持的动作类型映射
        self.action_mapping = {
            # 进程相关
            "exec": "execute",
            "execute": "execute",
            "fork": "fork",
            "clone": "fork",
            "exit": "exit",
            "kill": "terminate",
            "open": "open",
            "inject": "inject",
            "hide": "hide",

            # 文件相关
            "read": "read",
            "pread64": "read",
            "write": "write",
            "pwrite64": "write",
            "open": "open",
            "openat": "open",
            "unlink": "delete",
            "unlinkat": "delete",
            "create": "create",

            # 网络相关
            "connect": "connect",
            "accept": "accept",
            "accept4": "accept",
            "send": "send",
            "sendto": "send",
            "sendmsg": "send",
            "recv": "receive",
            "recvfrom": "receive",
            "recvmsg": "receive",
            "bind": "bind"
        }

    def extract_from_logs(self, log_data: Dict) -> List[Dict]:
        """
        从日志数据中提取统一格式的事件

        Args:
            log_data: 包含原始日志的字典

        Returns:
            List[Dict]: 统一格式的事件列表
        """
        events = []

        # 如果数据已经是统一格式，直接返回
        if "events" in log_data and self._is_unified_format(log_data["events"]):
            return log_data["events"]

        # 从原始日志提取
        raw_logs = log_data.get("raw_logs", [])

        for raw_log in raw_logs:
            event = self._extract_single_event(raw_log)
            if event:
                events.append(event)

        return events

    def _is_unified_format(self, events: List[Dict]) -> bool:
        """检查事件是否已经是统一格式"""
        if not events:
            return False
        first_event = events[0]
        return all(key in first_event for key in ["event_id", "timestamp", "subject", "action"])

    def _extract_single_event(self, raw_log: Dict) -> Dict:
        """从单条原始日志中提取事件"""
        log_type = raw_log.get("type", "")

        if log_type == "process":
            return self._extract_process_event(raw_log["data"])
        elif log_type == "file":
            return self._extract_file_event(raw_log["data"])
        elif log_type == "network":
            return self._extract_network_event(raw_log["data"])
        else:
            return self._extract_generic_event(raw_log)

    def _extract_process_event(self, data: Dict) -> Dict:
        """提取进程事件"""
        return {
            "event_id": data.get("event_id", f"evt_{datetime.now().timestamp()}"),
            "timestamp": data.get("timestamp", datetime.now().isoformat() + "Z"),
            "subject": {
                "type": "process",
                "id": data.get("subject", {}).get("id", ""),
                "name": data.get("subject", {}).get("name", ""),
                "pid": data.get("subject", {}).get("pid", 0),
                "ppid": data.get("subject", {}).get("ppid", 0),
                "path": data.get("subject", {}).get("path", ""),
                "cmdline": data.get("subject", {}).get("cmdline", "")
            },
            "object": data.get("object", {}),
            "action": self._normalize_action(data.get("action", "exec")),
            "attributes": data.get("attributes", {}),
            "log_type": "process",
            "label": data.get("label", "unknown"),
            "scenario_id": data.get("scenario_id", ""),
            "scenario_name": data.get("scenario_name", "")
        }

    def _extract_file_event(self, data: Dict) -> Dict:
        """提取文件事件"""
        return {
            "event_id": data.get("event_id", f"evt_{datetime.now().timestamp()}"),
            "timestamp": data.get("timestamp", datetime.now().isoformat() + "Z"),
            "subject": {
                "type": "process",
                "id": data.get("subject", {}).get("id", ""),
                "name": data.get("subject", {}).get("name", ""),
                "pid": data.get("subject", {}).get("pid", 0),
                "path": data.get("subject", {}).get("path", "")
            },
            "object": {
                "type": "file",
                "id": data.get("object", {}).get("id", ""),
                "path": data.get("object", {}).get("path", ""),
                "size": data.get("object", {}).get("size", 0)
            },
            "action": self._normalize_action(data.get("action", "read")),
            "attributes": data.get("attributes", {}),
            "log_type": "file",
            "label": data.get("label", "unknown"),
            "scenario_id": data.get("scenario_id", ""),
            "scenario_name": data.get("scenario_name", "")
        }

    def _extract_network_event(self, data: Dict) -> Dict:
        """提取网络事件"""
        obj = data.get("object", {})
        return {
            "event_id": data.get("event_id", f"evt_{datetime.now().timestamp()}"),
            "timestamp": data.get("timestamp", datetime.now().isoformat() + "Z"),
            "subject": {
                "type": "process",
                "id": data.get("subject", {}).get("id", ""),
                "name": data.get("subject", {}).get("name", ""),
                "pid": data.get("subject", {}).get("pid", 0),
                "path": data.get("subject", {}).get("path", "")
            },
            "object": {
                "type": "socket",
                "id": obj.get("id", ""),
                "ip": obj.get("ip", ""),
                "port": obj.get("port", 0)
            },
            "action": self._normalize_action(data.get("action", "connect")),
            "attributes": data.get("attributes", {}),
            "log_type": "network",
            "label": data.get("label", "unknown"),
            "scenario_id": data.get("scenario_id", ""),
            "scenario_name": data.get("scenario_name", "")
        }

    def _extract_generic_event(self, raw_log: Dict) -> Dict:
        """提取通用事件"""
        data = raw_log.get("data", raw_log)
        return {
            "event_id": data.get("event_id", f"evt_{datetime.now().timestamp()}"),
            "timestamp": data.get("timestamp", datetime.now().isoformat() + "Z"),
            "subject": data.get("subject", {}),
            "object": data.get("object", {}),
            "action": self._normalize_action(data.get("action", "unknown")),
            "attributes": data.get("attributes", {}),
            "log_type": raw_log.get("type", "unknown"),
            "label": data.get("label", "unknown")
        }

    def _normalize_action(self, action: str) -> str:
        """标准化动作名称"""
        return self.action_mapping.get(action.lower(), action.lower())

    def get_event_statistics(self, events: List[Dict]) -> Dict:
        """
        获取事件统计信息

        Args:
            events: 事件列表

        Returns:
            Dict: 统计信息
        """
        stats = {
            "total_events": len(events),
            "by_type": {},
            "by_action": {},
            "by_label": {},
            "time_range": {}
        }

        # 按类型统计
        for event in events:
            log_type = event.get("log_type", "unknown")
            action = event.get("action", "unknown")
            label = event.get("label", "unknown")

            stats["by_type"][log_type] = stats["by_type"].get(log_type, 0) + 1
            stats["by_action"][action] = stats["by_action"].get(action, 0) + 1
            stats["by_label"][label] = stats["by_label"].get(label, 0) + 1

        # 时间范围
        if events:
            timestamps = [e.get("timestamp", "") for e in events if e.get("timestamp")]
            if timestamps:
                stats["time_range"] = {
                    "start": min(timestamps),
                    "end": max(timestamps)
                }

        return stats


if __name__ == "__main__":
    # 测试事件提取
    from modules.data_generator import DataGenerator

    # 生成测试数据
    print("生成测试数据...")
    generator = DataGenerator()
    log_data = generator.generate(total_events=1000)

    # 提取事件
    print("提取事件...")
    extractor = EventExtractor()
    events = extractor.extract_from_logs(log_data)

    # 统计
    stats = extractor.get_event_statistics(events)
    print(f"事件统计: {json.dumps(stats, indent=2, ensure_ascii=False)}")
