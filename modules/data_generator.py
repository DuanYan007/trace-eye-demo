# -*- coding: utf-8 -*-
"""
数据生成模块
负责生成模拟的系统日志数据，包括进程、文件、网络三类日志
包含 15 种攻击场景的模拟数据
"""

import json
import random
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any


class DataGenerator:
    """系统日志数据生成器"""

    def __init__(self):
        # 初始化实体池
        self.process_pool = self._init_process_pool()
        self.file_pool = self._init_file_pool()
        self.network_pool = self._init_network_pool()
        self.attack_scenarios = self._init_attack_scenarios()

        # 生成状态
        self.current_time = datetime(2025, 3, 20, 10, 0, 0)
        self.event_counter = 0
        self.entity_counter = 0

    def _init_process_pool(self) -> Dict:
        """初始化进程实体池，总实体控制在 100-200 个"""
        return {
            "benign": [
                # 浏览器类
                {"name": "chrome", "base_pid": 1000, "count": 20, "path": "/usr/bin/chrome"},
                {"name": "firefox", "base_pid": 2000, "count": 20, "path": "/usr/bin/firefox"},
                {"name": "safari", "base_pid": 2100, "count": 10, "path": "/usr/bin/safari"},

                # 开发工具
                {"name": "vscode", "base_pid": 3000, "count": 15, "path": "/usr/bin/code"},
                {"name": "vim", "base_pid": 3100, "count": 10, "path": "/usr/bin/vim"},
                {"name": "nano", "base_pid": 3200, "count": 8, "path": "/usr/bin/nano"},

                # 系统工具
                {"name": "bash", "base_pid": 4000, "count": 25, "path": "/bin/bash"},
                {"name": "zsh", "base_pid": 4100, "count": 10, "path": "/bin/zsh"},
                {"name": "python3", "base_pid": 4200, "count": 12, "path": "/usr/bin/python3"},
                {"name": "node", "base_pid": 4300, "count": 8, "path": "/usr/bin/node"},

                # 系统服务
                {"name": "systemd", "base_pid": 1, "count": 5, "path": "/usr/sbin/systemd"},
                {"name": "sshd", "base_pid": 6000, "count": 10, "path": "/usr/sbin/sshd"},
                {"name": "nginx", "base_pid": 7000, "count": 8, "path": "/usr/sbin/nginx"},
                {"name": "docker", "base_pid": 5000, "count": 15, "path": "/usr/bin/docker"},
                {"name": "cron", "base_pid": 7100, "count": 5, "path": "/usr/sbin/cron"},

                # 其他常用程序
                {"name": "git", "base_pid": 4400, "count": 8, "path": "/usr/bin/git"},
                {"name": "curl", "base_pid": 4500, "count": 12, "path": "/usr/bin/curl"},
                {"name": "wget", "base_pid": 4600, "count": 10, "path": "/usr/bin/wget"},
                {"name": "tar", "base_pid": 4700, "count": 8, "path": "/usr/bin/tar"},
                {"name": "grep", "base_pid": 4800, "count": 8, "path": "/usr/bin/grep"},
                {"name": "sed", "base_pid": 4900, "count": 8, "path": "/usr/bin/sed"},
                {"name": "awk", "base_pid": 4950, "count": 5, "path": "/usr/bin/awk"},
            ],
            "malicious": [
                {"name": "dragon", "base_pid": 9000, "count": 5, "path": "/tmp/.dragon"},
                {"name": "backdoor", "base_pid": 9100, "count": 5, "path": "/var/tmp/.backdoor"},
                {"name": "injector", "base_pid": 9200, "count": 5, "path": "/dev/shm/.inject"},
                {"name": "miner", "base_pid": 9300, "count": 5, "path": "/tmp/.miner"},
                {"name": "keylogger", "base_pid": 9400, "count": 5, "path": "/tmp/.logd"},
                {"name": "ransomware", "base_pid": 9500, "count": 5, "path": "/tmp/.crypt"},
                {"name": "rootkit", "base_pid": 9600, "count": 5, "path": "/tmp/.rkmod"},
                {"name": "webshell", "base_pid": 9700, "count": 5, "path": "/var/www/.shell"},
                {"name": "stealer", "base_pid": 9800, "count": 5, "path": "/tmp/.steal"},
                {"name": "rat", "base_pid": 9900, "count": 5, "path": "/tmp/.rat"},
            ]
        }

    def _init_file_pool(self) -> Dict:
        """初始化文件实体池"""
        return {
            "benign": [
                # 用户目录
                "/home/user/documents/report.doc",
                "/home/user/documents/notes.txt",
                "/home/user/downloads/setup.exe",
                "/home/user/downloads/image.jpg",
                "/home/user/.bashrc",
                "/home/user/.ssh/config",
                "/home/user/.ssh/id_rsa",
                "/home/user/project/app.py",
                "/home/user/project/requirements.txt",
                "/home/user/project/main.c",

                # 系统目录
                "/etc/hosts",
                "/etc/hostname",
                "/etc/nginx.conf",
                "/etc/cron.d/daily",
                "/var/log/auth.log",
                "/var/log/syslog",
                "/var/www/index.html",
                "/var/www/css/style.css",
                "/tmp/session_1234",
                "/tmp/cache_file.tmp",

                # 库文件
                "/usr/lib/libc.so.6",
                "/usr/lib/libssl.so.1.1",
                "/usr/local/lib/custom.so",
                "/opt/app/lib/helper.so",
            ],
            "sensitive": [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/sudoers",
                "/root/.ssh/id_rsa",
                "/home/user/.ssh/id_rsa",
                "/var/log/auth.log",
                "/etc/ssh/sshd_config",
            ],
            "executable": [
                "/tmp/malware.bin",
                "/dev/shm/payload.so",
                "/var/tmp/update.bin",
                "/tmp/.hidden/exec",
            ]
        }

    def _init_network_pool(self) -> Dict:
        """初始化网络实体池"""
        return {
            "benign": [
                # 内网IP
                "192.168.1.1", "192.168.1.100", "192.168.1.254",
                "10.0.0.1", "10.0.0.50", "10.0.0.100",
                "172.16.0.1", "172.16.0.50",

                # 常见公网IP（白名单）
                "8.8.8.8",       # Google DNS
                "1.1.1.1",       # Cloudflare DNS
                "151.101.1.140", # GitHub
                "140.82.112.4",  # GitHub
                "13.107.42.14",  # Microsoft

                # 常用端口
                (80, "192.168.1.100"),   # HTTP
                (443, "192.168.1.100"),  # HTTPS
                (22, "192.168.1.1"),     # SSH
                (3306, "192.168.1.50"),  # MySQL
                (5432, "192.168.1.50"),  # PostgreSQL
            ],
            "malicious": [
                "146.153.68.151",   # 恶意广告服务器
                "161.116.88.72",    # C2 服务器
                "45.76.211.143",    # 已知恶意IP
                "103.20.10.50",     # 境外可疑IP
                "185.220.101.1",    # TOR出口节点
                "198.51.100.23",    # 采矿池
            ],
            "suspicious_ports": [
                4444,  # Metasploit
                5555,  # 常见木马
                6666,  # IRC Bot
                31337, # Back Orifice
                12345, # NetBus
            ]
        }

    def _init_attack_scenarios(self) -> List[Dict]:
        """初始化15种攻击场景"""
        return [
            {
                "id": "scen_001",
                "name": "Firefox后门植入",
                "type": "backdoor",
                "description": "通过Firefox漏洞下载恶意文件并执行后门",
                "techniques": ["T1190", "T1059", "T1071"],
                "steps": self._firefox_backdoor_steps()
            },
            {
                "id": "scen_002",
                "name": "供应链攻击",
                "type": "supply_chain",
                "description": "通过被篡改的软件包植入恶意代码",
                "techniques": ["T1195", "T1059"],
                "steps": self._supply_chain_steps()
            },
            {
                "id": "scen_003",
                "name": "权限提升",
                "type": "privilege_escalation",
                "description": "利用sudo提权漏洞获取root权限",
                "techniques": ["T1068"],
                "steps": self._privilege_escalation_steps()
            },
            {
                "id": "scen_004",
                "name": "数据窃取",
                "type": "data_exfiltration",
                "description": "扫描敏感文件并打包外传",
                "techniques": ["T1005", "T1041"],
                "steps": self._data_exfiltration_steps()
            },
            {
                "id": "scen_005",
                "name": "反向Shell",
                "type": "reverse_shell",
                "description": "建立反向Shell连接",
                "techniques": ["T1059"],
                "steps": self._reverse_shell_steps()
            },
            {
                "id": "scen_006",
                "name": "DLL注入",
                "type": "dll_injection",
                "description": "向合法进程注入恶意DLL",
                "techniques": ["T1055"],
                "steps": self._dll_injection_steps()
            },
            {
                "id": "scen_007",
                "name": "挖矿程序",
                "type": "crypto_mining",
                "description": "下载并运行挖矿程序",
                "techniques": ["T1496"],
                "steps": self._crypto_mining_steps()
            },
            {
                "id": "scen_008",
                "name": "持久化",
                "type": "persistence",
                "description": "修改启动项实现持久化",
                "techniques": ["T1547"],
                "steps": self._persistence_steps()
            },
            {
                "id": "scen_009",
                "name": "WebShell",
                "type": "webshell",
                "description": "上传WebShell并远程执行命令",
                "techniques": ["T1505"],
                "steps": self._webshell_steps()
            },
            {
                "id": "scen_010",
                "name": "内网扫描",
                "type": "network_scan",
                "description": "扫描内网主机和端口",
                "techniques": ["T1018", "T1046"],
                "steps": self._network_scan_steps()
            },
            {
                "id": "scen_011",
                "name": "凭证窃取",
                "type": "credential_theft",
                "description": "从内存中dump并提取密码",
                "techniques": ["T1003"],
                "steps": self._credential_theft_steps()
            },
            {
                "id": "scen_012",
                "name": "计划任务后门",
                "type": "scheduled_task",
                "description": "创建计划任务实现定时执行",
                "techniques": ["T1053"],
                "steps": self._scheduled_task_steps()
            },
            {
                "id": "scen_013",
                "name": "Rootkit加载",
                "type": "rootkit",
                "description": "加载内核模块隐藏进程",
                "techniques": ["T1014"],
                "steps": self._rootkit_steps()
            },
            {
                "id": "scen_014",
                "name": "中间人攻击",
                "type": "mitm",
                "description": "ARP欺骗劫持流量",
                "techniques": ["T1557"],
                "steps": self._mitm_steps()
            },
            {
                "id": "scen_015",
                "name": "容器逃逸",
                "type": "container_escape",
                "description": "从容器逃逸到宿主机",
                "techniques": ["T1611"],
                "steps": self._container_escape_steps()
            },
        ]

    # ========== 攻击场景步骤定义 ==========

    def _firefox_backdoor_steps(self):
        """Firefox后门植入攻击步骤"""
        return [
            {"action": "network", "type": "connect", "desc": "连接恶意广告服务器", "malicious": False},
            {"action": "network", "type": "recv", "desc": "接收恶意代码", "malicious": True},
            {"action": "file", "type": "write", "desc": "写入恶意文件到/tmp", "malicious": True},
            {"action": "process", "type": "exec", "desc": "执行恶意文件", "malicious": True},
            {"action": "network", "type": "connect", "desc": "连接C2服务器", "malicious": True},
            {"action": "file", "type": "read", "desc": "读取敏感文件", "malicious": True},
        ]

    def _supply_chain_steps(self):
        """供应链攻击步骤"""
        return [
            {"action": "process", "type": "exec", "desc": "执行apt install", "malicious": False},
            {"action": "network", "type": "connect", "desc": "连接被篡改的软件源", "malicious": True},
            {"action": "network", "type": "recv", "desc": "下载被篡改的包", "malicious": True},
            {"action": "file", "type": "write", "desc": "安装恶意包", "malicious": True},
            {"action": "process", "type": "exec", "desc": "执行恶意脚本", "malicious": True},
        ]

    def _privilege_escalation_steps(self):
        """权限提升步骤"""
        return [
            {"action": "process", "type": "exec", "desc": "执行sudo", "malicious": False},
            {"action": "file", "type": "read", "desc": "读取sudoers配置", "malicious": True},
            {"action": "file", "type": "write", "desc": "修改sudoers", "malicious": True},
            {"action": "process", "type": "exec", "desc": "获取root shell", "malicious": True},
        ]

    def _data_exfiltration_steps(self):
        """数据窃取步骤"""
        return [
            {"action": "file", "type": "read", "desc": "扫描文档目录", "malicious": False},
            {"action": "file", "type": "read", "desc": "读取敏感文件", "malicious": True},
            {"action": "file", "type": "write", "desc": "打包到压缩文件", "malicious": True},
            {"action": "network", "type": "connect", "desc": "连接外部服务器", "malicious": True},
            {"action": "network", "type": "send", "desc": "发送数据", "malicious": True},
        ]

    def _reverse_shell_steps(self):
        """反向Shell步骤"""
        return [
            {"action": "process", "type": "exec", "desc": "启动nc", "malicious": False},
            {"action": "network", "type": "connect", "desc": "连接攻击者服务器", "malicious": True},
            {"action": "process", "type": "exec", "desc": "绑定bash到socket", "malicious": True},
        ]

    def _dll_injection_steps(self):
        """DLL注入步骤"""
        return [
            {"action": "process", "type": "exec", "desc": "启动合法进程", "malicious": False},
            {"action": "process", "type": "open", "desc": "打开进程句柄", "malicious": True},
            {"action": "file", "type": "write", "desc": "写入恶意DLL", "malicious": True},
            {"action": "process", "type": "inject", "desc": "注入DLL", "malicious": True},
        ]

    def _crypto_mining_steps(self):
        """挖矿程序步骤"""
        return [
            {"action": "network", "type": "connect", "desc": "连接挖矿池", "malicious": True},
            {"action": "network", "type": "recv", "desc": "下载挖矿程序", "malicious": True},
            {"action": "file", "type": "write", "desc": "写入挖矿程序", "malicious": True},
            {"action": "process", "type": "exec", "desc": "启动挖矿进程", "malicious": True},
            {"action": "network", "type": "connect", "desc": "连接挖矿服务器", "malicious": True},
        ]

    def _persistence_steps(self):
        """持久化步骤"""
        return [
            {"action": "file", "type": "read", "desc": "读取启动配置", "malicious": False},
            {"action": "file", "type": "write", "desc": "修改启动项", "malicious": True},
            {"action": "file", "type": "write", "desc": "写入自启动脚本", "malicious": True},
        ]

    def _webshell_steps(self):
        """WebShell步骤"""
        return [
            {"action": "network", "type": "connect", "desc": "连接Web服务器", "malicious": False},
            {"action": "network", "type": "send", "desc": "上传恶意文件", "malicious": True},
            {"action": "file", "type": "write", "desc": "写入WebShell", "malicious": True},
            {"action": "network", "type": "recv", "desc": "接收命令执行", "malicious": True},
        ]

    def _network_scan_steps(self):
        """内网扫描步骤"""
        return [
            {"action": "network", "type": "connect", "desc": "扫描内网IP段", "malicious": True},
            {"action": "network", "type": "connect", "desc": "端口扫描", "malicious": True},
            {"action": "network", "type": "connect", "desc": "服务识别", "malicious": True},
        ]

    def _credential_theft_steps(self):
        """凭证窃取步骤"""
        return [
            {"action": "process", "type": "exec", "desc": "启动内存dump工具", "malicious": True},
            {"action": "file", "type": "write", "desc": "保存内存dump", "malicious": True},
            {"action": "file", "type": "read", "desc": "提取密码哈希", "malicious": True},
        ]

    def _scheduled_task_steps(self):
        """计划任务后门步骤"""
        return [
            {"action": "file", "type": "read", "desc": "读取crontab", "malicious": False},
            {"action": "file", "type": "write", "desc": "添加恶意计划任务", "malicious": True},
        ]

    def _rootkit_steps(self):
        """Rootkit加载步骤"""
        return [
            {"action": "file", "type": "write", "desc": "写入内核模块", "malicious": True},
            {"action": "process", "type": "exec", "desc": "insmod加载模块", "malicious": True},
            {"action": "process", "type": "hide", "desc": "隐藏恶意进程", "malicious": True},
        ]

    def _mitm_steps(self):
        """中间人攻击步骤"""
        return [
            {"action": "network", "type": "connect", "desc": "发送ARP欺骗包", "malicious": True},
            {"action": "network", "type": "recv", "desc": "劫持流量", "malicious": True},
        ]

    def _container_escape_steps(self):
        """容器逃逸步骤"""
        return [
            {"action": "process", "type": "exec", "desc": "挂载宿主机目录", "malicious": True},
            {"action": "file", "type": "read", "desc": "读取宿主机文件", "malicious": True},
        ]

    # ========== 日志生成方法 ==========

    def _get_process(self, malicious=False):
        """随机获取一个进程实体"""
        pool = self.process_pool["malicious"] if malicious else self.process_pool["benign"]
        proc = random.choice(pool)
        pid = proc["base_pid"] + random.randint(0, proc["count"] - 1)
        return {
            "type": "process",
            "id": f"proc_{pid}",
            "name": proc["name"],
            "pid": pid,
            "ppid": random.choice([1, 1000, 2000, 4000]),
            "path": proc["path"],
            "cmdline": f"{proc['name']} --flag"
        }

    def _get_file(self, sensitive=False, executable=False):
        """随机获取一个文件实体"""
        if executable:
            files = self.file_pool["executable"]
        elif sensitive:
            files = self.file_pool["sensitive"]
        else:
            files = self.file_pool["benign"]

        filepath = random.choice(files)
        return {
            "type": "file",
            "id": f"file_{hash(filepath) % 10000}",
            "path": filepath,
            "size": random.randint(1024, 1048576)
        }

    def _get_network(self, malicious=False):
        """随机获取网络连接信息"""
        if malicious:
            ip = random.choice(self.network_pool["malicious"])
            port = random.choice(self.network_pool["suspicious_ports"])
        else:
            ip = random.choice([x for x in self.network_pool["benign"] if isinstance(x, str)])
            port = random.choice([80, 443, 22, 3306, 5432, 8080])

        return {
            "type": "socket",
            "id": f"sock_{hash(ip) % 10000}_{port}",
            "ip": ip,
            "port": port
        }

    def _generate_process_event(self, action="exec", malicious=False):
        """生成进程事件"""
        subject = self._get_process(malicious)
        self.current_time += timedelta(milliseconds=random.randint(1, 100))
        self.event_counter += 1

        event = {
            "event_id": f"evt_{self.event_counter:05d}",
            "timestamp": self.current_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "subject": subject,
            "action": action,
            "attributes": {
                "return_code": random.choice([0, 0, 0, 1]),
                "duration_ms": random.randint(10, 5000)
            },
            "log_type": "process",
            "label": "malicious" if malicious else "benign"
        }

        if action == "fork":
            event["object"] = self._get_process(malicious)
        elif action in ["exec", "open"]:
            event["object"] = self._get_file(executable=malicious)

        return event

    def _generate_file_event(self, action="read", malicious=False, sensitive=False):
        """生成文件事件"""
        subject = self._get_process(malicious)
        obj = self._get_file(sensitive=sensitive, executable=malicious)
        self.current_time += timedelta(milliseconds=random.randint(1, 100))
        self.event_counter += 1

        event = {
            "event_id": f"evt_{self.event_counter:05d}",
            "timestamp": self.current_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "subject": subject,
            "object": obj,
            "action": action,
            "attributes": {
                "bytes": random.randint(64, 4096) if action == "read" else random.randint(64, 1024)
            },
            "log_type": "file",
            "label": "malicious" if malicious else "benign"
        }

        return event

    def _generate_network_event(self, action="connect", malicious=False):
        """生成网络事件"""
        subject = self._get_process(malicious)
        obj = self._get_network(malicious)
        self.current_time += timedelta(milliseconds=random.randint(1, 100))
        self.event_counter += 1

        event = {
            "event_id": f"evt_{self.event_counter:05d}",
            "timestamp": self.current_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "subject": subject,
            "object": obj,
            "action": action,
            "attributes": {
                "bytes_sent": random.randint(64, 4096),
                "bytes_recv": random.randint(64, 4096)
            },
            "log_type": "network",
            "label": "malicious" if malicious else "benign"
        }

        return event

    def _generate_attack_events(self, scenario):
        """生成单个攻击场景的事件"""
        events = []
        scenario_start_time = self.current_time

        for step in scenario["steps"]:
            action = step["action"]
            event_type = step["type"]
            is_malicious = step.get("malicious", False)

            if action == "process":
                if event_type == "exec":
                    events.append(self._generate_process_event("exec", is_malicious))
                elif event_type == "fork":
                    events.append(self._generate_process_event("fork", is_malicious))
                elif event_type == "open":
                    events.append(self._generate_process_event("open", is_malicious))
                elif event_type == "inject":
                    events.append(self._generate_process_event("inject", is_malicious))
                elif event_type == "hide":
                    events.append(self._generate_process_event("hide", is_malicious))

            elif action == "file":
                if event_type == "read":
                    events.append(self._generate_file_event("read", is_malicious, sensitive=is_malicious))
                elif event_type == "write":
                    events.append(self._generate_file_event("write", is_malicious))

            elif action == "network":
                if event_type == "connect":
                    events.append(self._generate_network_event("connect", is_malicious))
                elif event_type == "send":
                    events.append(self._generate_network_event("send", is_malicious))
                elif event_type == "recv":
                    events.append(self._generate_network_event("recv", is_malicious))

        # 为事件添加场景信息
        for evt in events:
            evt["scenario_id"] = scenario["id"]
            evt["scenario_name"] = scenario["name"]

        return {
            "scenario": scenario,
            "events": events,
            "start_time": scenario_start_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        }

    def _generate_benign_events(self, count):
        """生成正常行为事件"""
        events = []

        # 生成不同类型的正常事件
        event_generators = [
            lambda: self._generate_process_event("exec", False),
            lambda: self._generate_process_event("fork", False),
            lambda: self._generate_file_event("read", False, False),
            lambda: self._generate_file_event("write", False, False),
            lambda: self._generate_network_event("connect", False),
        ]

        for _ in range(count):
            generator = random.choice(event_generators)
            events.append(generator())

        return events

    def generate(self, total_events=40000, attack_ratio=0.15, output_dir=None):
        """
        生成完整的日志数据，保存为多源日志文件

        Args:
            total_events: 总事件数量
            attack_ratio: 攻击事件占比
            output_dir: 输出目录

        Returns:
            dict: 包含元数据、场景信息和所有事件的字典
        """
        import os

        if output_dir is None:
            output_dir = os.path.join(os.path.dirname(__file__), "..", "data")

        # 确保输出目录存在
        os.makedirs(output_dir, exist_ok=True)

        # 计算攻击和正常事件数量
        attack_count = int(total_events * attack_ratio)
        benign_count = total_events - attack_count

        # 重置状态
        self.current_time = datetime(2025, 3, 20, 10, 0, 0)
        self.event_counter = 0

        print(f"开始生成数据: 总事件 {total_events}, 攻击 {attack_count}, 正常 {benign_count}")

        # 生成攻击场景事件
        attack_scenarios_data = []
        attack_events = []

        # 选择要包含的攻击场景
        selected_scenarios = random.sample(self.attack_scenarios,
                                          min(len(self.attack_scenarios), 15))

        events_per_scenario = attack_count // len(selected_scenarios)

        for scenario in selected_scenarios:
            # 每个场景生成多轮攻击事件以增加数量
            scenario_events = []
            rounds = max(1, events_per_scenario // len(scenario["steps"]))

            for _ in range(rounds):
                scenario_data = self._generate_attack_events(scenario)
                scenario_events.extend(scenario_data["events"])

            attack_events.extend(scenario_events)
            attack_scenarios_data.append({
                "scenario": {
                    "id": scenario["id"],
                    "name": scenario["name"],
                    "type": scenario["type"],
                    "description": scenario["description"],
                    "techniques": scenario["techniques"]
                },
                "event_count": len(scenario_events)
            })

        # 限制攻击事件数量
        attack_events = attack_events[:attack_count]

        # 生成正常事件
        print("生成正常事件...")
        benign_events = self._generate_benign_events(benign_count)

        # 合并所有事件
        all_events = attack_events + benign_events

        # 按时间戳排序
        all_events.sort(key=lambda x: x["timestamp"])

        # 收集实体信息
        entities = self._collect_entities(all_events)

        # 计算实体总数
        entity_count = (len(entities["process"]) +
                       len(entities["file"]) +
                       len(entities["socket"]))

        # 分离多源日志
        process_events = [e for e in all_events if e.get("log_type") == "process"]
        file_events = [e for e in all_events if e.get("log_type") == "file"]
        network_events = [e for e in all_events if e.get("log_type") == "network"]

        # 生成统一的元数据
        meta = {
            "version": "2.0",
            "generated_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "total_events": len(all_events),
            "attack_events": len(attack_events),
            "benign_events": len(benign_events),
            "time_span": "1h",
            "entity_count": entity_count,
            "process_events": len(process_events),
            "file_events": len(file_events),
            "network_events": len(network_events)
        }

        # 保存多源日志文件
        log_files = {}

        # 1. 进程日志
        process_log = {
            "meta": {**meta, "log_type": "process", "event_count": len(process_events)},
            "entities": {"process": entities["process"]},
            "events": process_events
        }
        process_file = os.path.join(output_dir, "logs_process.json")
        with open(process_file, "w", encoding="utf-8") as f:
            json.dump(process_log, f, indent=2, ensure_ascii=False)
        log_files["process"] = process_file
        print(f"进程日志: {len(process_events)} 条 -> {process_file}")

        # 2. 文件日志
        file_log = {
            "meta": {**meta, "log_type": "file", "event_count": len(file_events)},
            "entities": {"file": entities["file"], "process": entities["process"]},
            "events": file_events
        }
        file_path = os.path.join(output_dir, "logs_file.json")
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(file_log, f, indent=2, ensure_ascii=False)
        log_files["file"] = file_path
        print(f"文件日志: {len(file_events)} 条 -> {file_path}")

        # 3. 网络日志
        network_log = {
            "meta": {**meta, "log_type": "network", "event_count": len(network_events)},
            "entities": {"socket": entities["socket"], "process": entities["process"]},
            "events": network_events
        }
        network_file = os.path.join(output_dir, "logs_network.json")
        with open(network_file, "w", encoding="utf-8") as f:
            json.dump(network_log, f, indent=2, ensure_ascii=False)
        log_files["network"] = network_file
        print(f"网络日志: {len(network_events)} 条 -> {network_file}")

        # 4. 保存完整的合并日志（用于向后兼容）
        result = {
            "meta": meta,
            "scenarios": attack_scenarios_data,
            "entities": entities,
            "events": all_events,
            "log_files": log_files
        }

        merged_file = os.path.join(output_dir, "data_logs.json")
        with open(merged_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"合并日志: {len(all_events)} 条 -> {merged_file}")

        print(f"数据生成完成: 总事件 {len(all_events)}, 实体 {entity_count}")
        print(f"  - 进程事件: {len(process_events)}")
        print(f"  - 文件事件: {len(file_events)}")
        print(f"  - 网络事件: {len(network_events)}")

        return result

    def _collect_entities(self, events):
        """从事件中收集所有实体"""
        entities = {
            "process": {},
            "file": {},
            "socket": {}
        }

        for event in events:
            # 收集主体实体
            subj = event["subject"]
            if subj["type"] in entities:
                entities[subj["type"]][subj["id"]] = subj

            # 收集客体实体
            if "object" in event:
                obj = event["object"]
                if obj["type"] in entities:
                    entities[obj["type"]][obj["id"]] = obj

        # 转换为列表
        return {
            "process": list(entities["process"].values()),
            "file": list(entities["file"].values()),
            "socket": list(entities["socket"].values())
        }


if __name__ == "__main__":
    # 测试数据生成
    generator = DataGenerator()
    data = generator.generate(total_events=4000)

    # 保存到文件
    output_file = "/home/duanyan/project/trace-eye-demo/data/data_logs.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"数据已保存到 {output_file}")
    print(f"总事件: {data['meta']['total_events']}")
    print(f"攻击事件: {data['meta']['attack_events']}")
    print(f"正常事件: {data['meta']['benign_events']}")
    print(f"实体数量: {data['meta']['entity_count']}")
    print(f"场景数量: {len(data['scenarios'])}")
