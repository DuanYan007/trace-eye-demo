# -*- coding: utf-8 -*-
"""
多源日志解析器
支持不同格式的日志文件解析，统一转换为事件格式
"""

import re
import json
from datetime import datetime
from typing import List, Dict, Any, Optional, Set


class LogParser:
    """多源日志解析器基类"""

    def __init__(self):
        # 可疑进程名称列表
        self.suspicious_processes = {
            ".hidden", "backdoor", "miner", "malware", "trojan",
            "keylogger", "rootkit", "shell", "inject", "payload"
        }

        # 可疑文件路径模式
        self.suspicious_path_patterns = [
            r"/tmp/\.",           # /tmp/ 下隐藏文件
            r"/dev/shm/",         # /dev/shm/ 下任何文件
            r"\.sh$",             # .sh 文件在某些位置
            r"\.php$",            # .php 在可疑位置
            r"\.exe$",            # .exe 文件
            r"\.dll$",            # .dll 文件
            r"\.so\.",            # .so 文件
            r"\.bin$",            # .bin 文件
        ]

        # 可疑端口
        self.suspicious_ports = {
            4444, 5555, 6666, 31337, 12345, 12346, 20000,
            44555, 54320, 54321
        }

        # 可疑IP段（常见C2服务器）
        self.suspicious_ips = {
            "103.20.10.50", "45.76.12.34"
        }

    def parse_file(self, file_path: str, log_type: str) -> List[Dict]:
        """解析日志文件"""
        parsers = {
            "process": self._parse_process_log,
            "file": self._parse_file_log,
            "network": self._parse_network_log,
            "json": self._parse_json_log
        }

        parser = parsers.get(log_type)
        if not parser:
            raise ValueError(f"不支持的日志类型: {log_type}")

        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        return parser(content, file_path)

    def _parse_process_log(self, content: str, source: str) -> List[Dict]:
        """
        解析进程日志 (syslog格式)
        格式: Mar 20 10:00:01 hostname process[pid]: message
        """
        events = []
        lines = content.strip().split('\n')

        # syslog 格式正则
        syslog_pattern = re.compile(
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\w+)(\[(\d+)\])?:\s*(.*)'
        )

        for line_num, line in enumerate(lines, 1):
            match = syslog_pattern.match(line)
            if not match:
                continue

            timestamp_str, hostname, process_name, _, pid, message = match.groups()

            # 解析时间戳
            try:
                # 假设当前年份
                timestamp = datetime.strptime(f"2025 {timestamp_str}", "%Y %b %d %H:%M:%S")
                timestamp = timestamp.isoformat() + "Z"
            except:
                timestamp = datetime.now().isoformat() + "Z"

            # 解析消息判断事件类型
            action, attributes = self._parse_process_message(message)

            # 判断是否为可疑进程
            is_suspicious = self._is_suspicious_process(process_name, message)

            # 创建进程实体
            proc_id = f"proc_{pid}" if pid else f"proc_{process_name}_{line_num}"

            event = {
                "event_id": f"proc_evt_{line_num}",
                "timestamp": timestamp,
                "log_type": "process",
                "source": source,
                "subject": {
                    "type": "process",
                    "id": proc_id,
                    "name": process_name,
                    "pid": int(pid) if pid else None,
                    "hostname": hostname
                },
                "action": action,
                "message": message,
                "attributes": attributes,
                "label": "malicious" if is_suspicious else "benign"
            }

            events.append(event)

        return events

    def _is_suspicious_process(self, process_name: str, message: str) -> bool:
        """判断进程是否可疑"""
        # 检查进程名称
        if process_name in self.suspicious_processes:
            return True

        # 检查消息中的可疑模式
        suspicious_keywords = [
            "reverse shell", "backdoor", "malware", "inject",
            "keylogger", "exfiltrating", "c2 server", "payload",
            "/tmp/.", "/dev/shm/", "base64 encoding", "privilege escalation"
        ]

        message_lower = message.lower()
        for keyword in suspicious_keywords:
            if keyword in message_lower:
                return True

        return False

    def _parse_process_message(self, message: str) -> tuple:
        """解析进程消息，提取动作和属性"""
        action = "unknown"
        attributes = {}

        # 执行动作
        if "executed" in message or "started" in message:
            action = "exec"
            match = re.search(r'executed\s+"([^"]+)"', message)
            if match:
                attributes["command"] = match.group(1)

        elif "forked" in message:
            action = "fork"
            match = re.search(r'forked\s+child\s+with\s+pid\s+(\d+)', message)
            if match:
                attributes["child_pid"] = int(match.group(1))

        elif "exited" in message:
            action = "exit"
            match = re.search(r'exited\s+with\s+status\s+(\d+)', message)
            if match:
                attributes["exit_status"] = int(match.group(1))

        elif "killed" in message:
            action = "kill"
            match = re.search(r'killed\s+by\s+signal\s+(\d+)', message)
            if match:
                attributes["signal"] = int(match.group(1))

        # 检测可疑行为
        if "/tmp/." in message or "/dev/shm/" in message:
            attributes["suspicious"] = True
        if "base64" in message or "decoded" in message:
            attributes["encoded"] = True

        return action, attributes

    def _parse_file_log(self, content: str, source: str) -> List[Dict]:
        """
        解析文件日志 (文件审计格式)
        格式: timestamp|pid|operation|path|result|details
        """
        events = []
        lines = content.strip().split('\n')

        for line_num, line in enumerate(lines, 1):
            parts = line.split('|')
            if len(parts) < 5:
                continue

            timestamp_str, pid, operation, path, result = parts[:5]
            details = parts[5] if len(parts) > 5 else ""

            # 解析时间戳
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00')).isoformat()
            except:
                timestamp = datetime.now().isoformat() + "Z"

            # 判断是否为可疑文件操作
            is_suspicious = self._is_suspicious_file_operation(path, operation, details)

            # 创建文件实体
            file_id = f"file_{hash(path) % 100000}"

            event = {
                "event_id": f"file_evt_{line_num}",
                "timestamp": timestamp,
                "log_type": "file",
                "source": source,
                "subject": {
                    "type": "process",
                    "id": f"proc_{pid}" if pid else f"proc_unknown_{line_num}",
                    "pid": int(pid) if pid.isdigit() else None
                },
                "object": {
                    "type": "file",
                    "id": file_id,
                    "path": path
                },
                "action": operation.lower(),
                "result": result.lower(),
                "attributes": {},
                "label": "malicious" if is_suspicious else "benign"
            }

            # 添加详情
            if details:
                try:
                    event["attributes"] = json.loads(details)
                except:
                    event["attributes"]["details"] = details

            events.append(event)

        return events

    def _is_suspicious_file_operation(self, path: str, operation: str, details: str) -> bool:
        """判断文件操作是否可疑"""
        # 检查路径模式
        for pattern in self.suspicious_path_patterns:
            if re.search(pattern, path):
                return True

        # 敏感路径
        sensitive_paths = {
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/root/.ssh", "/home/user/.ssh",
            "/etc/ssh/sshd_config"
        }

        # 敏感路径的非读操作
        if path in sensitive_paths and operation.upper() not in ["READ", "GET"]:
            return True

        # 检查详情中的可疑标记
        if details and "suspicious" in details.lower():
            return True

        return False

    def _parse_network_log(self, content: str, source: str) -> List[Dict]:
        """
        解析网络日志 (NetFlow格式)
        格式: timestamp,duration,src_ip,src_port,dst_ip,dst_port,protocol,bytes_in,bytes_out,flags
        """
        events = []
        lines = content.strip().split('\n')

        for line_num, line in enumerate(lines, 1):
            parts = line.split(',')
            if len(parts) < 9:
                continue

            timestamp_str, duration, src_ip, src_port, dst_ip, dst_port, protocol, bytes_in, bytes_out = parts[:9]
            flags = parts[9] if len(parts) > 9 else ""

            # 解析时间戳
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00')).isoformat()
            except:
                timestamp = datetime.now().isoformat() + "Z"

            # 判断是否为可疑网络连接
            is_suspicious = self._is_suspicious_connection(dst_ip, dst_port)

            # 创建socket实体
            socket_id = f"sock_{src_ip.replace('.', '_')}_{src_port}"

            event = {
                "event_id": f"net_evt_{line_num}",
                "timestamp": timestamp,
                "log_type": "network",
                "source": source,
                "subject": {
                    "type": "process",
                    "id": f"proc_unknown_{line_num}"
                },
                "object": {
                    "type": "socket",
                    "id": socket_id,
                    "src_ip": src_ip,
                    "src_port": int(src_port) if src_port.isdigit() else None,
                    "dst_ip": dst_ip,
                    "dst_port": int(dst_port) if dst_port.isdigit() else None,
                    "protocol": protocol
                },
                "action": "connect",
                "attributes": {
                    "duration": float(duration) if duration else 0,
                    "bytes_sent": int(bytes_out) if bytes_out and bytes_out.isdigit() else 0,
                    "bytes_recv": int(bytes_in) if bytes_in and bytes_in.isdigit() else 0,
                    "flags": flags
                },
                "label": "malicious" if is_suspicious else "benign"
            }

            events.append(event)

        return events

    def _is_suspicious_connection(self, dst_ip: str, dst_port: str) -> bool:
        """判断网络连接是否可疑"""
        # 检查可疑IP
        if dst_ip in self.suspicious_ips:
            return True

        # 检查可疑端口
        try:
            port = int(dst_port)
            if port in self.suspicious_ports:
                return True
        except (ValueError, TypeError):
            pass

        # 检查非标准端口（不是常见服务端口）
        common_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 6379, 8080}
        try:
            port = int(dst_port)
            # 短连接 + 高端口 + 非常用端口 = 可疑
            if port > 1024 and port not in common_ports:
                return True
        except (ValueError, TypeError):
            pass

        return False

    def _parse_json_log(self, content: str, source: str) -> List[Dict]:
        """解析JSON格式的日志"""
        events = []

        try:
            data = json.loads(content)
            if isinstance(data, dict):
                # 单个JSON对象或包含events数组的对象
                events_data = data.get("events", [data])
            elif isinstance(data, list):
                events_data = data
            else:
                return events

            for idx, event in enumerate(events_data):
                # 标准化事件格式
                normalized = {
                    "event_id": event.get("event_id", f"json_evt_{idx}"),
                    "timestamp": event.get("timestamp", datetime.now().isoformat() + "Z"),
                    "log_type": event.get("log_type", "unknown"),
                    "source": source,
                    "subject": event.get("subject", {}),
                    "object": event.get("object"),
                    "action": event.get("action", "unknown"),
                    "attributes": event.get("attributes", {}),
                    "label": event.get("label", "unknown")
                }
                events.append(normalized)

        except json.JSONDecodeError:
            # 可能是每行一个JSON
            for line_num, line in enumerate(content.strip().split('\n'), 1):
                try:
                    event = json.loads(line)
                    event["event_id"] = event.get("event_id", f"json_evt_{line_num}")
                    event["source"] = source
                    events.append(event)
                except:
                    continue

        return events


# 测试代码
if __name__ == "__main__":
    parser = LogParser()

    # 测试进程日志
    process_log = """Mar 20 10:00:01 server01 sshd[1234]: Accepted password for user from 192.168.1.100 port 22
Mar 20 10:00:02 server01 systemd[1]: Started User Manager for UID 1000
Mar 20 10:00:03 server01 python3[5678]: executed "/tmp/.hidden_script"
Mar 20 10:00:04 server01 bash[9999]: killed by signal 9"""

    print("=== 解析进程日志 ===")
    process_events = parser._parse_process_log(process_log, "syslog.log")
    print(f"解析到 {len(process_events)} 条事件")
    if process_events:
        print(f"示例: {json.dumps(process_events[0], indent=2, ensure_ascii=False)}")

    # 测试文件日志
    file_log = """2025-03-20T10:00:01Z|1234|READ|/etc/passwd|success|{"user": "root"}
2025-03-20T10:00:02Z|5678|WRITE|/tmp/malware.bin|success|{"size": 1024}
2025-03-20T10:00:03Z|9999|DELETE|/var/log/auth.log|success|{}"""

    print("\n=== 解析文件日志 ===")
    file_events = parser._parse_file_log(file_log, "audit.log")
    print(f"解析到 {len(file_events)} 条事件")
    if file_events:
        print(f"示例: {json.dumps(file_events[0], indent=2, ensure_ascii=False)}")

    # 测试网络日志
    network_log = """2025-03-20T10:00:01Z,5.2,192.168.1.100,45123,185.220.101.1,80,TCP,1024,2048,SA
2025-03-20T10:00:02Z,0.5,10.0.0.5,54321,103.20.10.50,31337,TCP,512,0,S"""

    print("\n=== 解析网络日志 ===")
    network_events = parser._parse_network_log(network_log, "netflow.log")
    print(f"解析到 {len(network_events)} 条事件")
    if network_events:
        print(f"示例: {json.dumps(network_events[0], indent=2, ensure_ascii=False)}")
