from scapy.all import sniff, Ether, IP
import tkinter as tk
from threading import Thread
import psutil


LOCAL_IP = "172.21.198.11"

stats = {
    'multicast': 0,
    'broadcast': 0,
    'local': 0,
    'received': 0
}


sniffing_thread = None
stop_sniffing = False


def handle_packet(packet):
    if stop_sniffing:
        return

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


def update_stats():
    global stats_labels
    stats_labels['multicast'].config(text=f"Multicast Packets: {stats['multicast']}")
    stats_labels['broadcast'].config(text=f"Broadcast Packets: {stats['broadcast']}")
    stats_labels['local'].config(text=f"Local Packets: {stats['local']}")
    stats_labels['received'].config(text=f"Received Packets: {stats['received']}")

    net_io_counters = psutil.net_io_counters(pernic=True)['en0']
    dropped_packets = net_io_counters.dropout + net_io_counters.dropin
    stats_labels['dropped'].config(text=f"Dropped Packets: {dropped_packets}")
    
    if not stop_sniffing:
        root.after(1000, update_stats)  # 如果没有停止，每秒刷新一次统计数据

def toggle_sniffing():
    global sniffing_thread, stop_sniffing, LOCAL_IP
    try:
        LOCAL_IP = ip_entry.get() # 获取用户输入的IP地址
        if sniffing_thread is None or not sniffing_thread.is_alive():
            # 启动嗅探线程
            stop_sniffing = False
            sniffing_thread = Thread(target=lambda: sniff(prn=handle_packet, store=False), daemon=True)
            sniffing_thread.start()
            update_stats() # 开始更新GUI统计数据
            start_button.config(text="停止统计")
        else:
            # 停止嗅探线程
            stop_sniffing = True
            sniffing_thread.join() # 等待嗅探线程结束
            start_button.config(text="开始统计")
    except Exception as e:
        logging.exception("Exception occurred while toggling sniffing: %s", str(e))

def init_interface():
    global if_name

    if_name = 'en0'


root = tk.Tk()
root.title("Network Traffic Monitor")


ip_label = tk.Label(root, text="本地IP地址:")
ip_label.pack()
ip_entry = tk.Entry(root)
ip_entry.insert(0, LOCAL_IP)
ip_entry.pack()


stats_labels = {
    'multicast': tk.Label(root, text="Multicast Packets: 0"),
    'broadcast': tk.Label(root, text="Broadcast Packets: 0"),
    'local': tk.Label(root, text="Local Packets: 0"),
    'received': tk.Label(root, text="Received Packets: 0"),
    'dropped': tk.Label(root, text="Dropped Packets: 0")
}


for label in stats_labels.values():
    label.pack()


start_button = tk.Button(root, text="开始统计", command=toggle_sniffing)
stats_labels['dropped'].pack()
start_button.pack()
init_interface()

root.mainloop()