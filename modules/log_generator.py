# -*- coding: utf-8 -*-
"""
多源日志生成器
生成不同格式的日志文件，模拟真实场景
"""

import os
import json
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any


class MultiFormatLogGenerator:
    """多格式日志生成器"""

    def __init__(self):
        self.start_time = datetime(2025, 3, 20, 10, 0, 0)
        self.current_time = self.start_time

        # 实体池
        self.processes = self._init_processes()
        self.files = self._init_files()
        self.networks = self._init_networks()

    def _init_processes(self) -> List[Dict]:
        """初始化进程实体"""
        return [
            {"name": "sshd", "pid_base": 1000, "count": 20, "suspicious": False},
            {"name": "systemd", "pid_base": 1, "count": 5, "suspicious": False},
            {"name": "bash", "pid_base": 4000, "count": 30, "suspicious": False},
            {"name": "python3", "pid_base": 5000, "count": 15, "suspicious": False},
            {"name": "nginx", "pid_base": 6000, "count": 10, "suspicious": False},
            {"name": "cron", "pid_base": 7000, "count": 5, "suspicious": False},
            # 可疑进程
            {"name": ".hidden", "pid_base": 9000, "count": 5, "suspicious": True},
            {"name": "backdoor", "pid_base": 9100, "count": 5, "suspicious": True},
            {"name": "miner", "pid_base": 9200, "count": 5, "suspicious": True},
        ]

    def _init_files(self) -> List[Dict]:
        """初始化文件实体"""
        return [
            # 正常文件
            {"path": "/etc/passwd", "suspicious": False},
            {"path": "/etc/hosts", "suspicious": False},
            {"path": "/etc/shadow", "suspicious": False},
            {"path": "/home/user/.ssh/id_rsa", "suspicious": False},
            {"path": "/home/user/documents/report.doc", "suspicious": False},
            {"path": "/var/log/auth.log", "suspicious": False},
            {"path": "/var/log/syslog", "suspicious": False},
            {"path": "/tmp/test.txt", "suspicious": False},
            # 可疑文件
            {"path": "/tmp/.hidden_script", "suspicious": True},
            {"path": "/dev/shm/.malware", "suspicious": True},
            {"path": "/tmp/backdoor.bin", "suspicious": True},
            {"path": "/var/www/.shell.php", "suspicious": True},
            {"path": "/etc/cron.d/.hack", "suspicious": True},
        ]

    def _init_networks(self) -> List[Dict]:
        """初始化网络实体"""
        return [
            # 正常连接
            {"src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "dst_port": 53, "protocol": "UDP", "suspicious": False},
            {"src_ip": "192.168.1.100", "dst_ip": "185.220.101.1", "dst_port": 80, "protocol": "TCP", "suspicious": False},
            {"src_ip": "192.168.1.100", "dst_ip": "151.101.1.140", "dst_port": 443, "protocol": "TCP", "suspicious": False},
            # 可疑连接
            {"src_ip": "192.168.1.100", "dst_ip": "103.20.10.50", "dst_port": 31337, "protocol": "TCP", "suspicious": True},
            {"src_ip": "192.168.1.100", "dst_ip": "185.220.101.1", "dst_port": 6666, "protocol": "TCP", "suspicious": True},
            {"src_ip": "192.168.1.100", "dst_ip": "45.76.12.34", "dst_port": 4444, "protocol": "TCP", "suspicious": True},
        ]

    def generate_all(self, output_dir: str, total_events: int = 40000):
        """生成所有格式的日志文件"""

        os.makedirs(output_dir, exist_ok=True)

        # 分配事件数量 - 添加随机波动，避免太整齐
        base_ratio = 1.0 / 3
        variance = 0.1  # 10% 波动

        process_ratio = base_ratio + random.uniform(-variance, variance)
        file_ratio = base_ratio + random.uniform(-variance, variance)
        network_ratio = 1.0 - process_ratio - file_ratio

        process_count = int(total_events * process_ratio)
        file_count = int(total_events * file_ratio)
        network_count = int(total_events * network_ratio)

        # 调整使总数匹配
        adjustment = total_events - (process_count + file_count + network_count)
        file_count += adjustment  # 将差值加到文件日志

        print(f"开始生成多格式日志文件:")
        print(f"  进程日志: {process_count} 条")
        print(f"  文件日志: {file_count} 条")
        print(f"  网络日志: {network_count} 条")

        # 1. 生成进程日志 (syslog格式)
        process_file = os.path.join(output_dir, "syslog.log")
        self._generate_process_log(process_file, process_count)
        print(f"  ✓ {process_file}")

        # 2. 生成文件日志 (审计格式)
        file_audit = os.path.join(output_dir, "file_audit.log")
        self._generate_file_log(file_audit, file_count)
        print(f"  ✓ {file_audit}")

        # 3. 生成网络日志 (NetFlow格式)
        netflow_file = os.path.join(output_dir, "netflow.log")
        self._generate_network_log(netflow_file, network_count)
        print(f"  ✓ {netflow_file}")

        # 4. 生成元数据文件
        meta_file = os.path.join(output_dir, "metadata.json")
        self._generate_metadata(meta_file, process_count, file_count, network_count)
        print(f"  ✓ {meta_file}")

        print(f"\n日志生成完成! 共 {total_events} 条事件")

    def _generate_process_log(self, filepath: str, count: int):
        """生成进程日志 (syslog格式)"""
        # 添加随机波动到实际行数
        actual_count = count + random.randint(-50, 50)
        actual_count = max(actual_count, int(count * 0.9))  # 至少90%

        with open(filepath, 'w', encoding='utf-8') as f:
            self.current_time = self.start_time

            for i in range(actual_count):
                # 随机选择进程
                proc = random.choice(self.processes)
                pid = proc["pid_base"] + random.randint(0, proc["count"] - 1)
                hostname = "server01"

                # 生成时间戳
                time_str = self.current_time.strftime("%b %d %H:%M:%S")
                self.current_time += timedelta(seconds=random.randint(1, 60))

                # 生成日志消息
                message = self._generate_process_message(proc)

                # syslog格式
                line = f"{time_str} {hostname} {proc['name']}[{pid}]: {message}\n"
                f.write(line)

    def _generate_process_message(self, proc: Dict) -> str:
        """生成进程日志消息"""
        messages = []

        if not proc["suspicious"]:
            # 正常进程消息
            messages = [
                "Started user session",
                "Accepted password for user from 192.168.1.50",
                "Session opened for user root",
                "Executing /usr/bin/python3 script.py",
                "Child process started with pid 1234",
                "Process exited with status 0",
                "Reloading configuration",
                "Listening on port 80",
                "Connection accepted from 192.168.1.100",
                "Scheduled task executed"
            ]
        else:
            # 可疑进程消息
            messages = [
                f"Executing /tmp/.hidden_script --decode",
                f"Established reverse shell to 103.20.10.50:31337",
                f"Injecting code into process {random.randint(1000, 9999)}",
                f"Reading /etc/shadow",
                f"Writing to /dev/shm/.malware",
                f"Base64 encoding data and exfiltrating",
                f"Connecting to C2 server 45.76.12.34:4444",
                f"Modifying /etc/cron.d/.hack",
                f"Keylogger active, capturing keystrokes",
                f"Privilege escalation successful"
            ]

        return random.choice(messages)

    def _generate_file_log(self, filepath: str, count: int):
        """生成文件日志 (审计格式)"""
        # 添加随机波动
        actual_count = count + random.randint(-100, 100)
        actual_count = max(actual_count, int(count * 0.85))

        with open(filepath, 'w', encoding='utf-8') as f:
            self.current_time = self.start_time

            operations = ["READ", "WRITE", "DELETE", "EXECUTE", "RENAME", "ATTRIBUTE"]

            for i in range(actual_count):
                file_entity = random.choice(self.files)
                proc = random.choice(self.processes)
                operation = random.choice(operations)

                # 生成时间戳
                time_str = self.current_time.isoformat() + "Z"
                self.current_time += timedelta(seconds=random.randint(1, 30))

                # 生成结果
                result = "success" if random.random() > 0.1 else "failure"

                # 生成详情
                if file_entity["suspicious"] and operation in ["READ", "WRITE"]:
                    details = f'{{"suspicious": true, "sequence": {i}}}'
                elif operation == "WRITE":
                    details = f'{{"size": {random.randint(1024, 1048576)}}}'
                else:
                    details = '{}'

                # 审计日志格式: timestamp|pid|operation|path|result|details
                pid = proc["pid_base"] + random.randint(0, proc["count"] - 1)
                line = f"{time_str}|{pid}|{operation}|{file_entity['path']}|{result}|{details}\n"
                f.write(line)

    def _generate_network_log(self, filepath: str, count: int):
        """生成网络日志 (NetFlow格式)"""
        # 添加随机波动
        actual_count = count + random.randint(-50, 50)
        actual_count = max(actual_count, int(count * 0.9))

        with open(filepath, 'w', encoding='utf-8') as f:
            self.current_time = self.start_time

            for i in range(actual_count):
                net_entity = random.choice(self.networks)
                proc = random.choice(self.processes)

                # 生成时间戳
                time_str = self.current_time.isoformat() + "Z"
                self.current_time += timedelta(seconds=random.randint(1, 10))

                # 生成连接参数
                duration = random.uniform(0.1, 300.5)
                bytes_in = random.randint(512, 10485760)
                bytes_out = random.randint(1024, 52428800)

                # 生成标志
                flags = ["S", "SA", "SAF", "SF", "R", "RA"]
                flag = random.choice(flags)

                if net_entity["suspicious"]:
                    # 可疑连接通常持续时间短，数据量大
                    duration = random.uniform(0.1, 10.0)
                    bytes_out = random.randint(1024, 102400)

                # NetFlow格式: timestamp,duration,src_ip,src_port,dst_ip,dst_port,protocol,bytes_in,bytes_out,flags
                src_port = random.randint(1024, 65535)
                line = f"{time_str},{duration:.1f},{net_entity['src_ip']},{src_port},{net_entity['dst_ip']},{net_entity['dst_port']},{net_entity['protocol']},{bytes_in},{bytes_out},{flag}\n"
                f.write(line)

    def _generate_metadata(self, filepath: str, process_count: int, file_count: int, network_count: int):
        """生成元数据文件"""
        metadata = {
            "version": "2.0",
            "generated_at": datetime.now().isoformat() + "Z",
            "total_events": process_count + file_count + network_count,
            "log_files": {
                "process": {
                    "file": "syslog.log",
                    "format": "syslog",
                    "event_count": process_count,
                    "description": "系统进程日志 (syslog格式)"
                },
                "file": {
                    "file": "file_audit.log",
                    "format": "audit",
                    "event_count": file_count,
                    "description": "文件访问审计日志 (管道分隔格式)"
                },
                "network": {
                    "file": "netflow.log",
                    "format": "netflow",
                    "event_count": network_count,
                    "description": "网络流量日志 (NetFlow格式)"
                }
            },
            "entities": {
                "process_count": len(self.processes),
                "file_count": len(self.files),
                "network_count": len(self.networks)
            }
        }

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    import sys
    sys.path.append('/home/duanyan/project/trace-eye-demo')

    generator = MultiFormatLogGenerator()
    generator.generate_all("data", total_events=40000)
