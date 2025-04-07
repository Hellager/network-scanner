#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import ipaddress
import threading
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Tuple

# 全局变量
scan_results = {}
scan_lock = threading.Lock()
progress_counter = 0
progress_lock = threading.Lock()
total_hosts = 0
active_hosts = 0


def clear_screen():
    """跨平台清屏函数"""
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")


def get_network_interfaces() -> Dict[str, str]:
    """获取系统上的网络接口"""
    interfaces = {}

    try:
        # 尝试使用socket获取网络接口信息
        if platform.system() == "Windows":
            # Windows平台使用ipconfig命令
            output = subprocess.check_output("ipconfig", shell=True).decode('gbk')
            lines = output.split('\n')
            current_if = None
            for line in lines:
                if "适配器" in line and ":" in line:
                    current_if = line.split(":")[0].strip()
                elif "IPv4 地址" in line and current_if:
                    ip = line.split(":")[1].strip().replace("(首选)", "")
                    interfaces[current_if] = ip
        else:
            # Unix/Linux/Mac平台
            import netifaces
            for iface in netifaces.interfaces():
                addresses = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addresses:
                    ip = addresses[netifaces.AF_INET][0]['addr']
                    interfaces[iface] = ip
    except Exception as e:
        print(f"获取网络接口时出错: {e}")
        # 回退方案：使用本地回环接口
        interfaces["lo"] = "127.0.0.1"

    return interfaces


def select_interface(interfaces: Dict[str, str]) -> Tuple[str, str]:
    """交互式选择网络接口"""
    clear_screen()
    print("可用网络接口:")
    print("-" * 50)

    if not interfaces:
        print("未找到网络接口")
        sys.exit(1)

    options = list(interfaces.items())
    for i, (name, ip) in enumerate(options):
        print(f"{i + 1}. {name}: {ip}")

    while True:
        try:
            choice = int(input("\n请选择网络接口 [1-{}]: ".format(len(options))))
            if 1 <= choice <= len(options):
                return options[choice - 1]
        except ValueError:
            pass
        print("无效选择，请重试")


def generate_ip_range(cidr: str) -> List[str]:
    """从CIDR表示法生成IP地址列表"""
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
        # 排除网络地址和广播地址
        if network.num_addresses > 2:
            return [str(ip) for ip in list(network.hosts())]
        else:
            return [str(ip) for ip in network]
    except Exception as e:
        print(f"生成IP范围时出错: {e}")
        return []


def ping_host(ip: str, timeout: float = 2.0) -> Tuple[bool, float]:
    """使用ICMP ping主机并返回状态和延迟"""
    if platform.system() == "Windows":
        # Windows平台使用系统ping命令
        try:
            output = subprocess.check_output(
                f"ping -n 1 -w {int(timeout * 1000)} {ip}",
                shell=True
            ).decode('gbk')

            if "TTL=" in output:
                # 提取延迟时间
                for line in output.split('\n'):
                    if "时间=" in line:
                        latency = float(line.split("时间=")[1].split("ms")[0].strip())
                        return True, latency
                return True, timeout * 1000
            return False, timeout * 1000
        except (Exception,):
            return False, timeout * 1000
    else:
        # Unix/Linux/Mac平台尝试使用原生ICMP
        try:
            import ping3
            ping3.EXCEPTIONS = True
            latency = ping3.ping(ip, timeout=int(timeout))
            if latency is not None:
                return True, latency * 1000  # 转换为毫秒
            return False, timeout * 1000
        except ImportError:
            # 如果没有ping3库，回退到系统ping命令
            try:
                output = subprocess.check_output(
                    f"ping -c 1 -W {int(timeout)} {ip}",
                    shell=True
                ).decode('utf-8')

                if " 0% packet loss" in output:
                    for line in output.split('\n'):
                        if "time=" in line:
                            latency = float(line.split("time=")[1].split(" ")[0])
                            return True, latency
                    return True, timeout * 1000
                return False, timeout * 1000
            except (Exception,):
                return False, timeout * 1000


def scan_worker(ip: str, timeout: float = 2.0) -> None:
    """扫描工作线程"""
    global scan_results, progress_counter, active_hosts

    is_alive, latency = ping_host(ip, timeout)

    # 使用锁保护共享数据结构
    with scan_lock:
        scan_results[ip] = {
            "status": is_alive,
            "latency": latency
        }
        if is_alive:
            active_hosts += 1

    # 更新进度计数器
    with progress_lock:
        global progress_counter
        progress_counter += 1


def display_progress():
    """显示扫描进度"""
    global progress_counter, total_hosts, active_hosts

    # 初始化进度显示
    clear_screen()
    last_progress = 0
    last_active = 0

    while progress_counter < total_hosts:
        # 只有当进度有变化时才更新显示
        if progress_counter > last_progress or active_hosts > last_active:
            progress = progress_counter / total_hosts
            bar_length = 50
            filled_length = int(bar_length * progress)

            bar = '█' * filled_length + '░' * (bar_length - filled_length)

            # 使用ANSI转义序列移动光标至行首并清除行
            print(f"\r\033[K网络扫描进度: [{bar}] {progress_counter}/{total_hosts} ({progress * 100:.1f}%)", end="")
            print(f"\n\033[K已发现活跃主机: {active_hosts}", end="")

            # 恢复光标位置
            print("\033[1A", end="")

            last_progress = progress_counter
            last_active = active_hosts

        time.sleep(0.2)

    # 最终更新，确保光标在正确位置
    print("\n\n")

    # 不在这里调用display_results，避免重复显示
    # 移除: display_results()


def display_results():
    """显示最终扫描结果"""
    global scan_results, total_hosts, active_hosts

    # 计算统计信息
    response_rate = (active_hosts / total_hosts) * 100 if total_hosts > 0 else 0

    # 获取活跃主机的延迟数据
    latencies = [data["latency"] for ip, data in scan_results.items() if data["status"]]

    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    min_latency = min(latencies) if latencies else 0
    max_latency = max(latencies) if latencies else 0

    print("扫描完成!")
    print(f"总计扫描主机: {total_hosts}")
    print(f"活跃主机数量: {active_hosts}")
    print(f"响应率: {response_rate:.1f}%")
    print(f"平均延迟: {avg_latency:.2f} ms")
    print(f"最小延迟: {min_latency:.2f} ms")
    print(f"最大延迟: {max_latency:.2f} ms")

    print("\n扫描结果:")
    print("-" * 60)
    print("| {:<15} | {:<10} | {:<15} |".format("IP地址", "状态", "延迟 (ms)"))
    print("-" * 60)

    # 按IP地址排序显示所有主机（包括无响应的主机）
    sorted_results = sorted(
        scan_results.items(),
        key=lambda x: [int(n) for n in x[0].split('.')]  # 按IP地址数值排序
    )

    for ip, data in sorted_results:
        status = "●" if data["status"] else "×"
        latency = data["latency"] if data["status"] else "-"
        if isinstance(latency, float):
            print("| {:<15} | {:<10} | {:<15.2f} |".format(
                ip, status, latency
            ))
        else:
            print("| {:<15} | {:<10} | {:<15} |".format(
                ip, status, latency
            ))

    print("-" * 60)


def main():
    """主函数"""
    global total_hosts

    try:
        clear_screen()
        print("网络扫描工具")
        print("=" * 50)

        # 获取并选择网络接口
        interfaces = get_network_interfaces()
        interface_name, interface_ip = select_interface(interfaces)

        # 确定要扫描的网络
        default_cidr = ".".join(interface_ip.split(".")[:3]) + ".0/24"
        cidr = input(f"请输入要扫描的CIDR (默认 {default_cidr}): ") or default_cidr

        # 生成IP地址列表
        ip_list = generate_ip_range(cidr)
        total_hosts = len(ip_list)

        if total_hosts == 0:
            print("没有有效的IP地址可供扫描")
            return

        print(f"将扫描 {total_hosts} 个主机...")
        time.sleep(1)

        # 创建进度显示线程
        progress_thread = threading.Thread(target=display_progress)
        progress_thread.daemon = True
        progress_thread.start()

        # 使用线程池执行扫描
        max_workers = min(200, total_hosts)  # 最大并发数
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for ip in ip_list:
                executor.submit(scan_worker, ip, 5)

        # 等待进度线程完成
        progress_thread.join(timeout=0.5)

        # 显示最终结果（只在这里调用一次）
        clear_screen()
        display_results()

    except KeyboardInterrupt:
        print("\n扫描已被用户中断")
    except Exception as e:
        print(f"发生错误: {e}")
    finally:
        print("\n按任意键退出...")
        try:
            input()
        except (Exception,):
            pass


if __name__ == "__main__":
    main()
