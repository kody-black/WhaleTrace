import sys
from PyQt5.QtWidgets import QApplication, QMainWindow

from WhaleUi import *
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
from PyQt5.QtCore import QThread

packet_id = 0


class MyThread(QThread):
    def __init__(self):
        super(Thread.self).__init__()


class MyMainwindow(WhaleUi, QMainWindow):
    def __init__(self):
        super(MyMainwindow, self).__init__()
        self.setupUi(self)

    def beginSniff(self):
        pkts = sniff(prn=lambda x: self.process_packet(x), count=4)

    def buttonClick(self):
        print("好好学习")
        sender = self.sender()
        self.statusBar().showMessage(sender.text() + ' was pressed')

    def process_packet(self, packet):
        PacketTime = str(packet.time)
        if Ether in packet:
            src = packet[Ether].src
            dst = packet[Ether].dst
            type = packet[Ether].type
            types = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x88cc: 'LLDP', 0x891D: 'TTE'}
            if type in types:
                proto = types[type]
            else:
                proto = 'LOOP'  # 协议
            # IP
            if proto == 'IPv4':
                # 建立协议查询字典
                protos = {1: 'ICMP', 2: 'IGMP', 4: 'IP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 41: 'IPv6', 50: 'ESP',
                          89: 'OSPF'}
                src = packet[IP].src
                dst = packet[IP].dst
                proto = packet[IP].proto
                if proto in protos:
                    proto = protos[proto]
            # TCP
            if TCP in packet:
                protos_tcp = {80: 'Http', 443: 'Https', 23: 'Telnet', 21: 'Ftp', 20: 'ftp_data', 22: 'SSH', 25: 'SMTP'}
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                # 获取端口信息
                if sport in protos_tcp:
                    proto = protos_tcp[sport]
                elif dport in protos_tcp:
                    proto = protos_tcp[dport]
            elif UDP in packet:
                if packet[UDP].sport == 53 or packet[UDP].dport == 53:
                    proto = 'DNS'
        else:
            return
            # src = packet[Dot3].src
            # dst = packet[Dot3].dst
            # proto = 'SNAP'    # 802.3
        length = len(packet)  # 长度
        print(length)
        info = packet.summary()  # 信息

        global packet_id
        item1 = QStandardItem(str(packet_id))
        item2 = QStandardItem(PacketTime)
        item3 = QStandardItem(src)
        item4 = QStandardItem(dst)
        item5 = QStandardItem(proto)
        item6 = QStandardItem(str(length))
        item7 = QStandardItem(info)
        self.model.setItem(packet_id, 0, item1)
        self.model.setItem(packet_id, 1, item2)
        self.model.setItem(packet_id, 2, item3)
        self.model.setItem(packet_id, 3, item4)
        self.model.setItem(packet_id, 4, item5)
        self.model.setItem(packet_id, 5, item6)
        self.model.setItem(packet_id, 6, item7)
        packet_id = packet_id + 1


if __name__ == '__main__':
    app = QApplication(sys.argv)
    myWindow = MyMainwindow()
    myWindow.show()
    sys.exit(app.exec_())
