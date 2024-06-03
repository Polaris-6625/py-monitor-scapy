from scapy.all import sniff, Ether, IP
import tkinter as tk
from threading import Thread

# 统计数据
stats = {
    'multicast': 0,
    'broadcast': 0,
    'local': 0,
    'received': 0
}

# 本地主机的IP地址（请根据实际情况替换）
LOCAL_IP = "172.21.198.11"

# 数据包处理回调函数
def handle_packet(packet):
    if packet.haslayer(Ether):
        dst_mac = packet[Ether].dst
        if dst_mac == "ff:ff:ff:ff:ff:ff":
            stats['broadcast'] += 1
        elif dst_mac.startswith("01:00:5e") or dst_mac.startswith("33:33"):
            stats['multicast'] += 1

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if src_ip == LOCAL_IP or dst_ip == LOCAL_IP:
            stats['local'] += 1

    stats['received'] += 1
    update_stats()

# 更新GUI统计数据
def update_stats():
    global stats_labels
    stats_labels['multicast'].config(text=f"Multicast Packets: {stats['multicast']}")
    stats_labels['broadcast'].config(text=f"Broadcast Packets: {stats['broadcast']}")
    stats_labels['local'].config(text=f"Local Packets: {stats['local']}")
    stats_labels['received'].config(text=f"Received Packets: {stats['received']}")
    root.after(1000, update_stats)  # 每秒刷新一次统计数据

# 启动数据包捕获线程
def start_sniffing():
    sniff(prn=handle_packet, store=False)

# 创建GUI
root = tk.Tk()
root.title("Network Traffic Monitor")

# 创建统计数据标签
stats_labels = {
    'multicast': tk.Label(root, text="Multicast Packets: 0"),
    'broadcast': tk.Label(root, text="Broadcast Packets: 0"),
    'local': tk.Label(root, text="Local Packets: 0"),
    'received': tk.Label(root, text="Received Packets: 0"),
}

# 放置统计数据标签
for label in stats_labels.values():
    label.pack()

# 启动捕获线程
thread = Thread(target=start_sniffing, daemon=True)
thread.start()

# 启动GUI循环
root.mainloop()