import sys
from PyQt5.QtWidgets import QApplication, QMainWindow

from WhaleUi import *
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

from PyQt5.QtCore import QThread
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

packet_id = 0
condi = ""
currentrow = 0

# 时间戳转为格式化时间
def timestamp2time(timestamp):
    time_array = time.localtime(timestamp)
    mytime = time.strftime("%H:%M:%S", time_array)
    return mytime


# 格式化时间转为时间戳
def time2timestamp(mytime):
    time_array = time.strptime(mytime, "%Y-%m-%d %H:%M:%S")
    return time.mktime(time_array)


class MyMainwindow(WhaleUi, QMainWindow):
    # 用来终止抓包线程的线程事件
    stop_sending = threading.Event()
    #finish = QtCore.pyqtSignal(int)

    def __init__(self):
        super(MyMainwindow, self).__init__()
        #super(InputDialogDemo, self).__init__(parent)
        self.setupUi(self)


    def beginSniff(self):
        sniffer_thread = threading.Thread(target=self.sniffer)
        sniffer_thread.setDaemon(True)
        sniffer_thread.start()
        self.actionStart2.setDisabled(True)
        self.actionStart.setDisabled(True)
        self.actionStop2.setDisabled(False)
        self.actionStop.setDisabled(False)

    def pauseSniff(self):
        self.stop_sending.set()
        self.actionStop2.setDisabled(True)
        self.actionStop.setDisabled(True)
        self.actionStart2.setDisabled(False)
        self.actionStart.setDisabled(False)
        self.actionRestart2.setDisabled(False)
        self.actionRestart.setDisabled(False)
#
    def restartSniff(self):
        lastRow = self.model.rowCount()
        print(lastRow)
        self.model.removeRows(0,lastRow)
        global packet_id
        packet_id = 0

    def sniffer(self):
        self.stop_sending.clear()
        #print(condi)
        pkts = sniff(filter=condi,prn=lambda x: self.process_packet(x),stop_filter=(lambda x: self.stop_sending.is_set()))
        #self.finish.emit(i)

    def actioncondi(self):
        global condi
        #condi = self.QuickFilterComboBox.currentText()
        condi=self.FilterEdit.text().lower()
        #暂时没想好文本框和下拉选项同时存在时怎么选
        #print(condi)
    def actionchoose(self):
        temp=self.QuickFilterComboBox.currentText().lower()
        self.FilterEdit.setText(temp)

    def screen(self,tag):
        rowcount = self.model.rowCount()
        #print(rowcount)
        #tag1 = tag.lower()
        a=0
        for i in range(0,rowcount):
            b=self.model.item(i-a,4)
            itemData=b.text()
            #print(b)
            if itemData != tag:
                self.model.removeRow(i-a)
                a=a+1
            #print(a)
    
    #打开和保存有问题，保存的话无法将获得的数据保存下来，是空文件
    def save(self):
        wrpcap("D:/temp.pcap",self.model)

    def open(self):
        self.model = rdpcap("y123.pcap",'rb')

    def click(self,item):
        global currentrow
        currentrow = item.row()

    def above(self):
        #currentrow = self.model.currentRow()
        #self.model.setcurrentRow(currentrow+1)
        #b=self.model.item(currentrow)
        
        #rowcount = self.model.rowCount()
        #print(rowcount)
        #tag1 = tag.lower()
        #i=0
        #for i in range(0,rowcount):
        #    if self.model.item(i,0).setSelected() == True:
        #        break
        global currentrow
        if currentrow > 0:
            currentrow = currentrow - 1
            #row=item
            b = self.tableView.selectRow(currentrow)
        
        #a = self.model.item(currentrow-1,0).row()
        #self.model.verticalScrollBar().setSliderPosition(a)
        
        #b=self.model.item(a-1,0).setSelected(True)
        #self.model.setSelectionBehavior(QAbstractItemView::SelectRows)

    def below(self):
        global currentrow
        rowcount = self.model.rowCount()
        if currentrow < rowcount-1:
           currentrow = currentrow+1
           b = self.tableView.selectRow(currentrow)
        

    def first(self):
        global currentrow
        currentrow = 0
        b = self.tableView.selectRow(0)

    def last(self):
        global currentrow
        rowcount = self.model.rowCount()
        currentrow = rowcount-1
        b = self.tableView.selectRow(rowcount-1)

    def get(self):
        num, ok = QInputDialog.getText(self, "输入你要转到的组","输入组编号")
        if ok and num : 
           global currentrow
           currentrow = num
           a = int(num)
           b = self.tableView.selectRow(a)
        
    def action1(self):
        con, ok = QInputDialog.getText(self, "过滤器","输入你的过滤条件")
        if ok and con :
            a = self.screen1(con)

    def screen1(self,leg):
        lent = len(leg)
        print(lent)
        if (leg[0] == 'i') and (lent>7):
            i=0
            nums = 0

            for i in range(0,lent):
                if leg[i]=='=':
                    nums = nums+1
                if nums == 2:
                    break
            level = i+2

            for i in range(level,lent):
                if leg[i]==' ':
                    break
            num = leg[level-1:i]
            tag1 = leg[i+1:lent]
            if tag1:
                l = self.screen(tag1)
            if tag1=="":
                num = leg[level-1:i+1]
            if leg[3] == 'a':
                l = self.screen2(num)
                
            elif leg[3] == 'd':
                l = self.screen3(num)

            else :
                l = self.screen4(num)

        else :
            l = self.screen(leg)


        #rowcount = self.model.rowCount()
        #print(rowcount)
        #tag1 = tag.lower()
        #a=0
        #for i in range(0,rowcount):
        #    b=self.model.item(i-a,4)
        #    itemData=b.text()
        #    #print(b)
        #    if itemData != tag:
        #        self.model.removeRow(i-a)
        #        a=a+1
    def screen2(self,tag):
        rowcount = self.model.rowCount()
        #print(rowcount)
        #tag1 = tag.lower()
        c=0
        for i in range(0,rowcount):
            a=self.model.item(i-c,2).text()
            b=self.model.item(i-c,3).text()
            #itemData=b.text()
            print("对比")
            print(b)
            print(tag)
            print("对比")
            if a != tag and b != tag :
                self.model.removeRow(i-c)
                c=c+1

    def screen3(self,tag):
        rowcount = self.model.rowCount()
        #print(rowcount)
        #tag1 = tag.lower()
        c=0
        for i in range(0,rowcount):
            #a=self.model.item(i-a,2).text()
            b=self.model.item(i-c,3).text()
            #itemData=b.text()
            print(b)
            if b != tag :
                self.model.removeRow(i-c)
                c=c+1        

    def screen4(self,tag):
        rowcount = self.model.rowCount()
        #print(rowcount)
        #tag1 = tag.lower()
        c=0
        for i in range(0,rowcount):
            a=self.model.item(i-c,2).text()
            #b=self.model.item(i-a,3).text()
            #itemData=b.text()
            print(a)
            if a != tag: #and b != tag :
                self.model.removeRow(i-c)
                c=c+1       
#a=self.model.item(i-a,2).text()
#                b=self.model.item(i-a,3).text()
#                if a != num or b != num:

    # def buttonClick(self):
    #     print("好好学习")
    #     sender = self.sender()
    #     self.statusBar().showMessage(sender.text() + ' was pressed')

    def process_packet(self, packet):
        realTime = timestamp2time(packet.time)
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
                #muliyiii='IPv4'
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
                #muliyiii='TCP'
                protos_tcp = {80: 'Http', 443: 'Https', 23: 'Telnet', 21: 'Ftp', 20: 'ftp_data', 22: 'SSH', 25: 'SMTP'}
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                # 获取端口信息
                if sport in protos_tcp:
                    proto = protos_tcp[sport]
                elif dport in protos_tcp:
                    proto = protos_tcp[dport]
            elif UDP in packet:
                #muliyiii='UDP'
                if packet[UDP].sport == 53 or packet[UDP].dport == 53:
                    proto = 'DNS'
        else:
            return
            # src = packet[Dot3].src
            # dst = packet[Dot3].dst
            # proto = 'SNAP'    # 802.3
        length = len(packet)  # 长度
        info = packet.summary()  # 信息
        global packet_id
        #if muliyiii == 'TCP':#WhaleUi.condi=='' or 
        item1 = QStandardItem(str(packet_id))
        item2 = QStandardItem(str(realTime))
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
    #demo=InputDialogDemo()
    #demo.show()
    sys.exit(app.exec_())
