from scapy.all import sniff, Ether, IP
import tkinter as tk
from threading import Thread
import logging
import psutil


# 为了保持两个窗口的独立状态，我们需要将状态和函数包装在一个类中
class PacketSniffer:
    def __init__(self, master, title):
        self.master = master
        self.master.title(title)

        self.stats = {
            'multicast': 0,
            'broadcast': 0,
            'local': 0,
            'received': 0
        }

        self.sniffing_thread = None
        self.stop_sniffing = False
        self.LOCAL_IP = "172.21.198.11"

        self.init_interface()
        self.create_widgets()

    def init_interface(self):
        global if_name

        if_name = 'en0'

    def handle_packet(self,packet):
        """
        处理数据包，统计不同类型数据包数量。

        Args:
            packet: 捕获到的数据包，类型为scapy.Packet。

        Returns:
            None。

        """
        # 如果停止嗅探，则返回
        if self.stop_sniffing:
            return

        # 如果数据包包含Ethernet层
        if packet.haslayer(Ether):
            # 获取目标MAC地址
            dst_mac = packet[Ether].dst
            # 如果目标MAC地址为广播地址
            if dst_mac == "ff:ff:ff:ff:ff:ff":
                # 广播数据包数量加1
                self.stats['broadcast'] += 1
            # 如果目标MAC地址以"01:00:5e"或"33:33"开头
            elif dst_mac.startswith("01:00:5e") or dst_mac.startswith("33:33"):
                # 组播数据包数量加1
                self.stats['multicast'] += 1

        # 如果数据包包含IP层
        if packet.haslayer(IP):
            # 获取源IP地址
            src_ip = packet[IP].src
            # 获取目标IP地址
            dst_ip = packet[IP].dst
            # 如果源IP地址或目标IP地址等于本地IP地址
            if src_ip == self.LOCAL_IP or dst_ip == self.LOCAL_IP:
                # 本地数据包数量加1
                self.stats['local'] += 1

        # 接收到的数据包数量加1
        self.stats['received'] += 1


    def update_stats(self):
        self.stats_labels['multicast'].config(text=f"多播包: {self.stats['multicast']}")
        self.stats_labels['broadcast'].config(text=f"广播包: {self.stats['broadcast']}")
        self.stats_labels['local'].config(text=f"本地: {self.stats['local']}")
        self.stats_labels['received'].config(text=f"接收: {self.stats['received']}")

        net_io_counters = psutil.net_io_counters(pernic=True)['en0']
        dropped_packets = net_io_counters.dropout + net_io_counters.dropin
        self.stats_labels['dropped'].config(text=f"丢失: {dropped_packets}")
        
        if not self.stop_sniffing:
            self.master.after(1000, self.update_stats)

    def toggle_sniffing(self):
        # global sniffing_thread, stop_sniffing, LOCAL_IP
        self.LOCAL_IP = self.ip_entry.get()
        try:
            self.LOCAL_IP = self.ip_entry.get() # 获取用户输入的IP地址
            if self.sniffing_thread is None or not self.sniffing_thread.is_alive():
                # 启动嗅探线程
                self.stop_sniffing = False
                self.sniffing_thread = Thread(target=lambda: sniff(prn=self.handle_packet, store=False), daemon=True)
                self.sniffing_thread.start()
                self.update_stats() # 开始更新GUI统计数据
                self.start_button.config(text="停止统计")
            else:
                # 停止嗅探线程
                self.stop_sniffing = True
                self.sniffing_thread.join() # 等待嗅探线程结束
                self.start_button.config(text="开始统计")
        except Exception as e:
            logging.exception("Exception occurred while toggling sniffing: %s", str(e))

    def create_widgets(self):
        # 添加IP地址输入框
        ip_label = tk.Label(self.master, text="请输入本地IP地址：")
        ip_label.pack()
        self.ip_entry = tk.Entry(self.master)
        self.ip_entry.insert(0, self.LOCAL_IP)
        self.ip_entry.pack()

        # 添加开始统计按钮
        self.start_button = tk.Button(self.master, text="开始统计", command=self.toggle_sniffing)
        self.start_button.pack()

        # 添加统计数据标签
        self.stats_labels = {
            'multicast': tk.Label(self.master, text="多播包: 0"),
            'broadcast': tk.Label(self.master, text="广播包: 0"),
            'local': tk.Label(self.master, text="本地: 0"),
            'received': tk.Label(self.master, text="接收: 0"),
            'dropped': tk.Label(self.master, text="丢失: 0")
        }

        for label in self.stats_labels.values():
            label.pack()

        # 添加新窗口按钮
        new_window_button = tk.Button(self.master, text="新窗口", command=self.open_new_window)
        new_window_button.pack()

    def open_new_window(self):
        new_window = tk.Tk()
        new_sniffer = PacketSniffer(new_window, "新窗口 - 网络流量统计软件")
        new_window.mainloop()


# 初始化主窗口
root = tk.Tk()
sniffer = PacketSniffer(root, "网络流量统计软件")
root.mainloop()