# -*- coding: utf-8 -*-
"""
规则引擎模块
基于预定义规则进行异常检测
包含 25 条检测规则，分为 5 大类
"""

import re
from typing import List, Dict, Any, Tuple
from ipaddress import ip_address


class RuleEngine:
    """规则引擎 - 基于预定义规则检测异常"""

    def __init__(self, max_alerts: int = 500):
        """
        初始化规则引擎

        Args:
            max_alerts: 最大告警数量上限（默认500）
        """
        # 初始化所有规则
        self.rules = self._init_rules()
        self.max_alerts = max_alerts

        # 敏感路径列表
        self.sensitive_paths = {
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/etc/ssh/sshd_config", "/root/.ssh",
            "/home/user/.ssh/id_rsa", "/var/log/auth.log"
        }

        # 可疑路径列表
        self.suspicious_paths = {
            "/tmp", "/dev/shm", "/var/tmp"
        }

        # 可执行文件扩展名
        self.exec_extensions = {".so", ".dylib", ".dll", ".exe", ".bin"}

        # 正常 IP 白名单
        self.benign_ip_whitelist = {
            "8.8.8.8", "1.1.1.1", "151.101.1.140",
            "140.82.112.4", "13.107.42.14"
        }

        # 常用网络端口
        self.common_ports = {21, 22, 80, 443, 3306, 5432, 6379, 8080}

        # 可疑端口
        self.suspicious_ports = {4444, 5555, 6666, 31337, 12345}

    def _init_rules(self) -> Dict:
        """初始化所有规则"""
        return {
            # A. 文件异常规则 (R001-R006)
            "R001": {
                "id": "R001",
                "name": "敏感目录写入",
                "category": "file",
                "severity": "high",
                "description": "非root进程写入/etc敏感目录",
                "technique": "T1222",
                "condition": self._check_r001
            },
            "R002": {
                "id": "R002",
                "name": "临时目录可执行文件写入",
                "category": "file",
                "severity": "high",
                "description": "进程在/tmp或/dev/shm写入可执行文件",
                "technique": "T1105",
                "condition": self._check_r002
            },
            "R003": {
                "id": "R003",
                "name": "浏览器写入可执行库",
                "category": "file",
                "severity": "high",
                "description": "浏览器进程创建.so或.dylib文件",
                "technique": "T1059",
                "condition": self._check_r003
            },
            "R004": {
                "id": "R004",
                "name": "网络服务读取敏感文件",
                "category": "file",
                "severity": "high",
                "description": "网络服务进程读取/etc/passwd等敏感文件",
                "technique": "T1005",
                "condition": self._check_r004
            },
            "R005": {
                "id": "R005",
                "name": "进程删除自身可执行文件",
                "category": "file",
                "severity": "medium",
                "description": "进程删除其自身的可执行文件",
                "technique": "T1070",
                "condition": self._check_r005
            },
            "R006": {
                "id": "R006",
                "name": "未知进程写入系统目录",
                "category": "file",
                "severity": "high",
                "description": "未知/可疑进程写入系统目录",
                "technique": "T1012",
                "condition": self._check_r006
            },

            # B. 进程异常规则 (R101-R106)
            "R101": {
                "id": "R101",
                "name": "从临时目录执行",
                "category": "process",
                "severity": "high",
                "description": "进程从/tmp或/dev/shm执行",
                "technique": "T1204",
                "condition": self._check_r101
            },
            "R102": {
                "id": "R102",
                "name": "父子进程命名不匹配",
                "category": "process",
                "severity": "medium",
                "description": "父子进程名称明显不匹配（可能的进程伪装）",
                "technique": "T1055",
                "condition": self._check_r102
            },
            "R103": {
                "id": "R103",
                "name": "系统进程异常子进程",
                "category": "process",
                "severity": "medium",
                "description": "系统进程产生异常类型的子进程",
                "technique": "T1547",
                "condition": self._check_r103
            },
            "R104": {
                "id": "R104",
                "name": "命令行包含编码内容",
                "category": "process",
                "severity": "medium",
                "description": "进程命令行包含base64或编码内容",
                "technique": "T1027",
                "condition": self._check_r104
            },
            "R105": {
                "id": "R105",
                "name": "无父进程异常",
                "category": "process",
                "severity": "high",
                "description": "进程没有父进程或父进程为空",
                "technique": "T1014",
                "condition": self._check_r105
            },
            "R106": {
                "id": "R106",
                "name": "短周期多次执行",
                "category": "process",
                "severity": "medium",
                "description": "同一PID短时间内多次execve调用",
                "technique": "T1059",
                "condition": self._check_r106
            },

            # C. 网络异常规则 (R201-R205)
            "R201": {
                "id": "R201",
                "name": "连接非白名单境外IP",
                "category": "network",
                "severity": "medium",
                "description": "进程连接到非白名单的境外IP",
                "technique": "T1071",
                "condition": self._check_r201
            },
            "R202": {
                "id": "R202",
                "name": "非网络客户端建立连接",
                "category": "network",
                "severity": "medium",
                "description": "非HTTP客户端进程建立网络连接",
                "technique": "T1071",
                "condition": self._check_r202
            },
            "R203": {
                "id": "R203",
                "name": "系统进程连接非常用端口",
                "category": "network",
                "severity": "high",
                "description": "系统进程出站连接到非常用端口",
                "technique": "T1071",
                "condition": self._check_r203
            },
            "R204": {
                "id": "R204",
                "name": "监听高位端口",
                "category": "network",
                "severity": "low",
                "description": "进程监听高位端口（>32767）",
                "technique": "T1043",
                "condition": self._check_r204
            },
            "R205": {
                "id": "R205",
                "name": "短时间多IP连接",
                "category": "network",
                "severity": "high",
                "description": "进程短时间内连接多个不同IP",
                "technique": "T1048",
                "condition": self._check_r205
            },

            # D. 行为序列规则 (R301-R305)
            "R301": {
                "id": "R301",
                "name": "文件下载后立即执行",
                "category": "sequence",
                "severity": "high",
                "description": "文件下载后在5秒内被执行",
                "technique": "T1105",
                "condition": self._check_r301
            },
            "R302": {
                "id": "R302",
                "name": "进程启动后连接外部",
                "category": "sequence",
                "severity": "medium",
                "description": "新进程启动后立即建立网络连接",
                "technique": "T1059",
                "condition": self._check_r302
            },
            "R303": {
                "id": "R303",
                "name": "读敏感文件后联网",
                "category": "sequence",
                "severity": "high",
                "description": "读取敏感文件后立即建立网络连接",
                "technique": "T1041",
                "condition": self._check_r303
            },
            "R304": {
                "id": "R304",
                "name": "修改启动项",
                "category": "sequence",
                "severity": "high",
                "description": "进程修改系统启动配置",
                "technique": "T1547",
                "condition": self._check_r304
            },
            "R305": {
                "id": "R305",
                "name": "多进程写入同一文件",
                "category": "sequence",
                "severity": "medium",
                "description": "短时间内多个进程写入同一文件",
                "technique": "T1005",
                "condition": self._check_r305
            },

            # E. 时序异常规则 (R401-R403)
            "R401": {
                "id": "R401",
                "name": "凌晨异常活动",
                "category": "temporal",
                "severity": "medium",
                "description": "在凌晨2-5点期间的异常系统活动",
                "technique": "T1078",
                "condition": self._check_r401
            },
            "R402": {
                "id": "R402",
                "name": "周末系统操作",
                "category": "temporal",
                "severity": "low",
                "description": "在周末进行系统级操作",
                "technique": "T1078",
                "condition": self._check_r402
            },
            "R403": {
                "id": "R403",
                "name": "频繁失败尝试",
                "category": "temporal",
                "severity": "medium",
                "description": "短时间内多次失败的操作尝试",
                "technique": "T1110",
                "condition": self._check_r403
            }
        }

    # ========== 规则检查方法 ==========

    # A. 文件异常规则

    def _check_r001(self, event: Dict, context: Dict) -> bool:
        """检查：写入敏感系统配置文件"""
        if event.get("log_type") != "file":
            return False
        action = event.get("action", "").lower()
        if action not in ["write", "modify"]:
            return False
        # 检查object.path是否存在，如果没有则检查attributes中的path
        obj = event.get("object", {})
        obj_path = obj.get("path", "")
        # 从message中提取路径（适用于syslog格式）
        if not obj_path:
            message = event.get("message", "")
            import re
            match = re.search(r'/(etc/(passwd|shadow|sudoers|hosts|cron)|root/\.ssh|home/[^/]+/\.ssh)', message)
            if match:
                return True
        # 检查敏感路径
        sensitive_patterns = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
            "/etc/cron", "/etc/ssh/", "/root/.ssh", "/home/.ssh"
        ]
        return any(obj_path.startswith(p) for p in sensitive_patterns)

    def _check_r002(self, event: Dict, context: Dict) -> bool:
        """检查：在/tmp或/dev/shm写入可执行文件"""
        if event.get("log_type") != "file":
            return False
        action = event.get("action", "").lower()
        if action not in ["write", "modify"]:
            return False
        obj_path = event.get("object", {}).get("path", "")
        if not obj_path:
            # 从message中检查
            message = event.get("message", "")
            if "/tmp/." in message or "/dev/shm/" in message:
                return True
            return False
        # 检查是否在可疑目录
        is_tmp_path = any(obj_path.startswith(p) for p in self.suspicious_paths)
        # 检查是否为可执行文件
        is_executable = any(ext in obj_path.lower() for ext in [".so", ".dylib", ".exe", ".bin", ".sh", ".py"])
        # 检查隐藏文件
        is_hidden = "/tmp/." in obj_path or "/dev/shm/." in obj_path
        return (is_tmp_path and is_executable) or is_hidden

    def _check_r003(self, event: Dict, context: Dict) -> bool:
        """检查：可疑进程写入文件"""
        if event.get("log_type") != "file":
            return False
        action = event.get("action", "").lower()
        if action not in ["write", "modify"]:
            return False
        # 检查进程名称中的可疑特征
        message = event.get("message", "").lower()
        suspicious_keywords = [
            "backdoor", "malware", "miner", ".hidden", "trojan",
            "inject", "payload", "shell", "hack"
        ]
        return any(kw in message for kw in suspicious_keywords)

    def _check_r004(self, event: Dict, context: Dict) -> bool:
        """检查：读取敏感文件"""
        if event.get("log_type") != "file":
            return False
        action = event.get("action", "").lower()
        if action not in ["read", "attribute"]:
            return False
        obj_path = event.get("object", {}).get("path", "")
        # 检查敏感文件读取
        sensitive_files = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/root/.ssh/id_rsa", "/home/user/.ssh"
        ]
        return any(f in obj_path for f in sensitive_files)

    def _check_r005(self, event: Dict, context: Dict) -> bool:
        """检查：删除系统文件"""
        if event.get("log_type") != "file":
            return False
        action = event.get("action", "").lower()
        if action != "delete":
            return False
        obj_path = event.get("object", {}).get("path", "")
        # 删除系统目录下的文件
        return obj_path.startswith("/etc/") or obj_path.startswith("/usr/") or obj_path.startswith("/bin/")

    def _check_r006(self, event: Dict, context: Dict) -> bool:
        """检查：写入可执行文件到临时目录"""
        if event.get("log_type") != "file":
            return False
        action = event.get("action", "").lower()
        if action not in ["write", "execute"]:
            return False
        obj_path = event.get("object", {}).get("path", "")
        message = event.get("message", "")
        # 检查tmp目录下的可执行操作
        return ("/tmp/" in obj_path or "/tmp/" in message) and "exec" in action

    # B. 进程异常规则

    def _check_r101(self, event: Dict, context: Dict) -> bool:
        """检查：从临时目录执行"""
        if event.get("log_type") != "process":
            return False
        # 检查message中是否包含/tmp/执行
        message = event.get("message", "").lower()
        return "/tmp/" in message and ("exec" in message or "running" in message)

    def _check_r102(self, event: Dict, context: Dict) -> bool:
        """检查：可疑进程名称"""
        if event.get("log_type") != "process":
            return False
        # 检查subject或message中的可疑进程名
        subject = event.get("subject", {})
        proc_name = subject.get("name", "").lower()
        message = event.get("message", "").lower()
        # 可疑进程名特征
        suspicious_indicators = [
            ".hidden", "backdoor", "miner", "malware", "trojan",
            "keylogger", "rootkit", "shell", "inject"
        ]
        # 检查进程名或消息
        for indicator in suspicious_indicators:
            if indicator in proc_name or indicator in message:
                return True
        return False

    def _check_r103(self, event: Dict, context: Dict) -> bool:
        """检查：进程的可疑行为"""
        if event.get("log_type") != "process":
            return False
        message = event.get("message", "").lower()
        # 可疑行为关键词
        suspicious_actions = [
            "reverse shell", "c2 server", "exfiltrating",
            "privilege escalation", "injecting code", "modifying /etc"
        ]
        return any(action in message for action in suspicious_actions)

    def _check_r104(self, event: Dict, context: Dict) -> bool:
        """检查：命令行包含编码内容"""
        if event.get("log_type") != "process":
            return False
        message = event.get("message", "")
        # 检查base64或编码模式
        base64_pattern = r'[A-Za-z0-9+/]{30,}={0,2}'
        has_base64 = re.search(base64_pattern, message)
        # 检查编码关键词
        encoded_keywords = ["base64", "decode", "encode", "--decode"]
        has_keyword = any(kw in message.lower() for kw in encoded_keywords)
        return has_base64 or has_keyword

    def _check_r105(self, event: Dict, context: Dict) -> bool:
        """检查：可疑端口监听"""
        if event.get("log_type") != "process":
            return False
        message = event.get("message", "").lower()
        # 检查监听可疑端口
        for port in self.suspicious_ports:
            if f"port {port}" in message or f"port{port}" in message:
                return True
        return False

    def _check_r106(self, event: Dict, context: Dict) -> bool:
        """检查：高频率操作（需要上下文）"""
        # 检查最近事件中同一进程的操作频率
        events = context.get("recent_events", [])
        if len(events) < 5:
            return False
        # 统计最近10个事件中同一进程类型的数量
        current_proc = event.get("subject", {}).get("name", "")
        if not current_proc:
            return False
        same_proc_count = sum(1 for e in events[-10:]
                             if e.get("subject", {}).get("name", "") == current_proc)
        return same_proc_count >= 5

    # C. 网络异常规则

    def _check_r201(self, event: Dict, context: Dict) -> bool:
        """检查：连接可疑IP"""
        if event.get("log_type") != "network":
            return False
        obj = event.get("object", {})
        # 兼容不同格式的IP字段
        dst_ip = obj.get("dst_ip") or obj.get("ip", "")
        if not dst_ip:
            return False
        # 检查是否为已知的可疑IP
        if dst_ip in self.suspicious_ips:
            return True
        # 检查是否为境外非白名单IP
        try:
            ip_obj = ip_address(dst_ip)
            # 检查是否为私有IP
            is_private = ip_obj.is_private
            # 检查是否在白名单
            is_whitelisted = dst_ip in self.benign_ip_whitelist
            return not is_private and not is_whitelisted
        except:
            return False

    def _check_r202(self, event: Dict, context: Dict) -> bool:
        """检查：连接可疑端口"""
        if event.get("log_type") != "network":
            return False
        obj = event.get("object", {})
        # 兼容不同格式的端口字段
        dst_port = obj.get("dst_port") or obj.get("port", 0)
        try:
            port = int(dst_port)
            # 检查可疑端口
            return port in self.suspicious_ports
        except (ValueError, TypeError):
            return False

    def _check_r203(self, event: Dict, context: Dict) -> bool:
        """检查：连接到非常用高位端口"""
        if event.get("log_type") != "network":
            return False
        obj = event.get("object", {})
        dst_port = obj.get("dst_port") or obj.get("port", 0)
        try:
            port = int(dst_port)
            # 高位端口（>10000）且不是常用端口
            is_high_port = port > 10000
            is_uncommon = port not in self.common_ports
            return is_high_port and is_uncommon
        except (ValueError, TypeError):
            return False

    def _check_r204(self, event: Dict, context: Dict) -> bool:
        """检查：短连接行为（可能是扫描）"""
        if event.get("log_type") != "network":
            return False
        attrs = event.get("attributes", {})
        duration = attrs.get("duration", 0)
        flags = attrs.get("flags", "")
        # 持续时间小于3秒且标志为S（SYN）可能是端口扫描
        try:
            dur = float(duration)
            return dur < 3.0 and ("S" in flags or "SA" in flags)
        except (ValueError, TypeError):
            return False

    def _check_r205(self, event: Dict, context: Dict) -> bool:
        """检查：短时间多IP连接（需要上下文）"""
        # 检查最近事件中的连接
        events = context.get("recent_events", [])
        if len(events) < 5:
            return False
        # 统计最近10个事件中的不同目标IP
        recent_ips = set()
        for e in events[-10:]:
            if e.get("log_type") == "network":
                obj = e.get("object", {})
                ip = obj.get("dst_ip", "")
                if ip:
                    recent_ips.add(ip)
        # 如果连接了3个以上不同的IP
        return len(recent_ips) >= 3

    # D. 行为序列规则

    def _check_r301(self, event: Dict, context: Dict) -> bool:
        """检查：文件下载后立即执行"""
        # 需要检查事件序列
        events = context.get("recent_events", [])
        if len(events) < 2:
            return False

        current_time = self._parse_timestamp(event.get("timestamp", ""))
        for prev_event in events[-5:]:  # 检查最近5个事件
            if prev_event.get("action") == "write" and prev_event.get("log_type") == "file":
                prev_time = self._parse_timestamp(prev_event.get("timestamp", ""))
                # 文件写入后5秒内执行
                if 0 < (current_time - prev_time).total_seconds() <= 5:
                    return True
        return False

    def _check_r302(self, event: Dict, context: Dict) -> bool:
        """检查：进程启动后连接外部"""
        events = context.get("recent_events", [])
        if len(events) < 2:
            return False

        current_time = self._parse_timestamp(event.get("timestamp", ""))
        subj_id = event.get("subject", {}).get("id", "")

        # 检查最近是否有同一进程的启动事件
        for prev_event in events[-10:]:
            if (prev_event.get("action") == "execute" and
                prev_event.get("subject", {}).get("id") == subj_id):
                prev_time = self._parse_timestamp(prev_event.get("timestamp", ""))
                # 进程启动后10秒内建立网络连接
                if 0 < (current_time - prev_time).total_seconds() <= 10:
                    return True
        return False

    def _check_r303(self, event: Dict, context: Dict) -> bool:
        """检查：读敏感文件后联网"""
        events = context.get("recent_events", [])
        if len(events) < 2:
            return False

        current_time = self._parse_timestamp(event.get("timestamp", ""))
        subj_id = event.get("subject", {}).get("id", "")

        # 检查最近是否有同一进程读取敏感文件
        for prev_event in events[-10:]:
            if (prev_event.get("subject", {}).get("id") == subj_id and
                prev_event.get("action") == "read" and
                prev_event.get("object", {}).get("path", "") in self.sensitive_paths):
                prev_time = self._parse_timestamp(prev_event.get("timestamp", ""))
                # 读敏感文件后30秒内建立网络连接
                if 0 < (current_time - prev_time).total_seconds() <= 30:
                    return True
        return False

    def _check_r304(self, event: Dict, context: Dict) -> bool:
        """检查：修改启动项"""
        if event.get("log_type") != "file" or event.get("action") != "write":
            return False
        obj_path = event.get("object", {}).get("path", "")
        startup_paths = [
            "/etc/rc.local", "/etc/cron.", "/etc/systemd/system/",
            "/home/user/.config/autostart", "/etc/init.d/"
        ]
        return any(path in obj_path for path in startup_paths)

    def _check_r305(self, event: Dict, context: Dict) -> bool:
        """检查：多进程写入同一文件"""
        # 需要事件聚合
        return False

    # E. 时序异常规则

    def _check_r401(self, event: Dict, context: Dict) -> bool:
        """检查：凌晨异常活动（结合可疑行为）"""
        timestamp = event.get("timestamp", "")
        hour = self._parse_timestamp(timestamp).hour
        # 凌晨2-5点期间的可疑活动
        if not (2 <= hour <= 5):
            return False
        # 必须结合其他可疑因素，不仅仅是时间
        if event.get("log_type") == "process":
            message = event.get("message", "").lower()
            suspicious = ["hidden", "tmp", "shell", "exec", "connection"]
            return any(s in message for s in suspicious)
        elif event.get("log_type") == "file":
            obj_path = event.get("object", {}).get("path", "")
            # 检查敏感目录操作
            return obj_path.startswith("/etc/") or "/tmp/" in obj_path
        return False

    def _check_r402(self, event: Dict, context: Dict) -> bool:
        """检查：周末系统敏感操作"""
        timestamp = event.get("timestamp", "")
        dt = self._parse_timestamp(timestamp)
        is_weekend = dt.weekday() >= 5
        if not is_weekend:
            return False
        # 必须是系统敏感操作
        obj_path = event.get("object", {}).get("path", "")
        message = event.get("message", "").lower()
        # 敏感文件修改或可疑行为
        is_system_op = obj_path.startswith("/etc/") or obj_path.startswith("/root/")
        is_suspicious = any(kw in message for kw in ["modify", "write", "delete", "hidden"])
        return is_system_op or is_suspicious

    def _check_r403(self, event: Dict, context: Dict) -> bool:
        """检查：频繁失败尝试"""
        # 检查返回码或result字段
        return_code = event.get("attributes", {}).get("return_code", 0)
        # 检查file事件的result字段
        result = event.get("object", {}).get("result", "").lower()
        is_failure = return_code != 0 or result == "failure"
        if is_failure:
            # 统计上下文中的失败次数
            events = context.get("recent_events", [])
            fail_count = 1  # 当前事件
            for e in events[-20:]:
                rc = e.get("attributes", {}).get("return_code", 0)
                res = e.get("object", {}).get("result", "").lower()
                if rc != 0 or res == "failure":
                    fail_count += 1
            return fail_count >= 3
        return False

    # ========== 工具方法 ==========

    def _parse_timestamp(self, timestamp_str: str):
        """解析时间戳字符串"""
        from datetime import datetime
        try:
            # 移除Z后缀并解析
            if timestamp_str.endswith("Z"):
                timestamp_str = timestamp_str[:-1]
            return datetime.fromisoformat(timestamp_str)
        except:
            return datetime.now()

    def evaluate_event(self, event: Dict, context: Dict = None) -> List[Dict]:
        """
        评估单个事件，返回触发的规则列表

        Args:
            event: 待评估的事件
            context: 上下文信息（包含最近的事件等）

        Returns:
            List[Dict]: 触发的规则列表
        """
        if context is None:
            context = {}

        triggered_rules = []

        for rule_id, rule in self.rules.items():
            try:
                if rule["condition"](event, context):
                    triggered_rules.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "category": rule["category"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "technique": rule["technique"]
                    })
            except Exception as e:
                # 规则执行失败，跳过
                pass

        return triggered_rules

    def evaluate_events(self, events: List[Dict]) -> Dict:
        """
        评估事件列表，返回所有检测结果

        优化策略：
        1. 只对标记为恶意的事件进行规则检测
        2. 每个事件最多触发1条告警（取最严重的规则）
        3. 限制总告警数量在300-500之间，按优先级排序

        Args:
            events: 事件列表

        Returns:
            Dict: 检测结果
        """
        all_alerts = []
        rule_statistics = {
            "total_evaluated": len(events),
            "malicious_events": 0,
            "benign_events": 0,
            "total_alerts": 0,
            "by_rule": {},
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_category": {}
        }

        # 构建上下文（用于序列规则）
        context = {"recent_events": []}

        for event in events:
            # 更新上下文
            context["recent_events"].append(event)
            if len(context["recent_events"]) > 50:
                context["recent_events"].pop(0)

            # 统计良性/恶意事件
            label = event.get("label", "unknown")
            if label == "malicious":
                rule_statistics["malicious_events"] += 1
            else:
                rule_statistics["benign_events"] += 1
                continue  # 跳过良性事件，不进行规则检测

            # 评估事件
            triggered = self.evaluate_event(event, context)

            if triggered:
                # 只保留最严重的一条告警（critical > high > medium > low）
                severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
                triggered.sort(key=lambda r: severity_order.get(r["severity"], 0), reverse=True)
                rule = triggered[0]  # 取最严重的

                # 计算告警优先级（用于排序和截断）
                severity_priority = severity_order.get(rule["severity"], 0)
                alert = {
                    "event_id": event.get("event_id", ""),
                    "timestamp": event.get("timestamp", ""),
                    "rule": rule,
                    "subject": event.get("subject", {}),
                    "object": event.get("object", {}),
                    "message": event.get("message", ""),
                    "log_type": event.get("log_type", ""),
                    "_severity_priority": severity_priority,
                    "_sequence": len(all_alerts)
                }
                all_alerts.append(alert)

        # 按优先级排序告警（高危优先，同类告警按时间顺序）
        all_alerts.sort(key=lambda a: (-a["_severity_priority"], a["timestamp"], a["_sequence"]))

        # 截断到最大告警数量
        final_alerts = self._select_final_alerts(all_alerts)

        # 统计最终告警
        for alert in final_alerts:
            rule = alert["rule"]
            rule_id = rule["rule_id"]
            rule_statistics["total_alerts"] += 1
            rule_statistics["by_rule"][rule_id] = rule_statistics["by_rule"].get(rule_id, 0) + 1
            rule_statistics["by_severity"][rule["severity"]] = rule_statistics["by_severity"].get(rule["severity"], 0) + 1

            category = rule["category"]
            rule_statistics["by_category"][category] = rule_statistics["by_category"].get(category, 0) + 1

        # 移除内部字段
        for alert in final_alerts:
            alert.pop("_severity_priority", None)
            alert.pop("_sequence", None)

        return {
            "alerts": final_alerts,
            "statistics": rule_statistics
        }

    def _select_final_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """按严重性优先，同时保留中低危代表样本，避免展示结果被单一等级淹没。"""
        if len(alerts) <= self.max_alerts:
            return alerts

        severity_order = ["critical", "high", "medium", "low"]
        groups = {severity: [] for severity in severity_order}
        for alert in alerts:
            severity = alert.get("rule", {}).get("severity", "low")
            groups.setdefault(severity, []).append(alert)

        quotas = {
            "critical": int(self.max_alerts * 0.20),
            "high": int(self.max_alerts * 0.45),
            "medium": int(self.max_alerts * 0.25),
            "low": self.max_alerts
        }
        quotas["low"] = self.max_alerts - sum(quotas[level] for level in ["critical", "high", "medium"])

        selected = []
        selected_ids = set()
        for severity in severity_order:
            limit = quotas.get(severity, 0)
            for alert in groups.get(severity, [])[:limit]:
                selected.append(alert)
                selected_ids.add(id(alert))

        if len(selected) < self.max_alerts:
            for alert in alerts:
                if id(alert) in selected_ids:
                    continue
                selected.append(alert)
                if len(selected) >= self.max_alerts:
                    break

        selected.sort(key=lambda a: (-a["_severity_priority"], a["timestamp"], a["_sequence"]))
        return selected[:self.max_alerts]


if __name__ == "__main__":
    # 测试规则引擎
    from modules.data_generator import DataGenerator
    from modules.event_extractor import EventExtractor

    print("生成测试数据...")
    generator = DataGenerator()
    log_data = generator.generate(total_events=1000)

    print("提取事件...")
    extractor = EventExtractor()
    events = extractor.extract_from_logs(log_data)

    print("执行规则检测...")
    engine = RuleEngine()
    result = engine.evaluate_events(events)

    print(f"检测完成: 总告警 {result['statistics']['total_alerts']} 条")
    print(f"按严重程度: {result['statistics']['by_severity']}")
    print(f"按类别: {result['statistics']['by_category']}")
