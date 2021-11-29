# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'WhaleTrace.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.Qt import (QSplitter)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QIcon

#condi = "udp"
#condi = ""
class WhaleUi(object):
    #global condi
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("WhaleTrace")
        MainWindow.resize(1087, 830)
        MainWindow.setWindowIcon(QIcon('./icon/whale.jpg'))
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setSpacing(0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.FilterEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.FilterEdit.setInputMask("")
        self.FilterEdit.setText("")
        self.FilterEdit.setDragEnabled(False)
        self.FilterEdit.setObjectName("FilterEdit")
        self.text = self.FilterEdit.text()
        self.horizontalLayout.addWidget(self.FilterEdit)
        self.QuickFilterComboBox = QtWidgets.QComboBox(self.centralwidget)
        self.QuickFilterComboBox.setCurrentText("")
        self.QuickFilterComboBox.setObjectName("QuickFilterComboBox")
        self.QuickFilterComboBox.addItems(['', 'TCP', 'UDP', 'ICMP', 'ARP', 'IPv4', 'IPv6'])
        self.horizontalLayout.addWidget(self.QuickFilterComboBox)
        self.FilterButton = QtWidgets.QPushButton(self.centralwidget)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("icon/filter.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.FilterButton.setIcon(icon)
        self.FilterButton.setObjectName("FilterButton")
        
        self.horizontalLayout.addWidget(self.FilterButton)
        self.horizontalLayout.setStretch(0, 9)
        self.horizontalLayout.setStretch(2, 1)
        self.verticalLayout.addLayout(self.horizontalLayout)

        self.tableView = QtWidgets.QTableView(self.centralwidget)
        self.tableView.setDragEnabled(False)
        self.tableView.setObjectName("tableView")

        # 下面设置表格内容
        self.model = QStandardItemModel()
        # 设置水平方向的头标签文本内容
        self.model.setHorizontalHeaderLabels(['编号', '时间', '源地址', '目的地址', '协议', '长度', '信息'])

        # # 示例：设置每个位置的文本值
        # item1 = QStandardItem('1')
        # item2 = QStandardItem('2021-11-21 12:14:50')
        # item3 = QStandardItem('192.168.123.12')
        # item4 = QStandardItem('10.164.132.142')
        # item5 = QStandardItem('IPv4')
        # item6 = QStandardItem('215')
        # item7 = QStandardItem('Ether / IP / TCP 192.168.235.208:rrac > 172.217.163.51:https PA / Raw')
        # self.model.setItem(0,0,item1)
        # self.model.setItem(0,1,item2)
        # self.model.setItem(0,2,item3)
        # self.model.setItem(0,3,item4)
        # self.model.setItem(0,4,item5)
        # self.model.setItem(0,5,item6)
        # self.model.setItem(0,6,item7)

        # 实例化表格视图，设置模型为自定义的模型
        self.tableView.setModel(self.model)
        # 设置行列高宽随内容变化
        self.tableView.setColumnWidth(0,40)
        self.tableView.setColumnWidth(1,100)
        self.tableView.setColumnWidth(2,150)
        self.tableView.setColumnWidth(3,150)
        self.tableView.setColumnWidth(4,50)
        self.tableView.setColumnWidth(5,50)
        self.tableView.setColumnWidth(6,400)
        # self.tableView.resizeColumnsToContents()
        self.tableView.resizeRowsToContents()
        # 水平方向标签拓展剩下的窗口部分，填满表格
        self.tableView.horizontalHeader().setStretchLastSection(True)
        # 水平方向，表格大小拓展到适当的尺寸
        # self.tableView.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tableView.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)  # 不可编辑
        self.tableView.setAlternatingRowColors(True)  # 颜色交替
        self.tableView.verticalHeader().setVisible(False) #隐藏垂直标题
        self.columnView = QtWidgets.QColumnView(self.centralwidget)
        self.columnView.setDragEnabled(False)
        self.columnView.setObjectName("columnView")
        # 利用splitter控件实现可调整上下表格大小
        self.splitter1 = QSplitter(Qt.Vertical)
        self.splitter1.addWidget(self.tableView)
        self.splitter1.addWidget(self.columnView)
        self.splitter1.setStretchFactor(0,6)
        self.splitter1.setStretchFactor(1,3)
        self.verticalLayout.addWidget(self.splitter1)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1087, 26))
        self.menubar.setObjectName("menubar")
        self.menuFile = QtWidgets.QMenu(self.menubar)
        self.menuFile.setObjectName("menuFile")
        self.menuGoto = QtWidgets.QMenu(self.menubar)
        self.menuGoto.setGeometry(QtCore.QRect(344, 187, 137, 174))
        self.menuGoto.setObjectName("menuGoto")
        self.menuSniff = QtWidgets.QMenu(self.menubar)
        self.menuSniff.setObjectName("menuSniff")
        self.menuAnalyze = QtWidgets.QMenu(self.menubar)
        self.menuAnalyze.setObjectName("menuAnalyze")
        self.menuQuickFilter = QtWidgets.QMenu(self.menuAnalyze)
        self.menuQuickFilter.setObjectName("menuQuickFilter")
        self.menuTools = QtWidgets.QMenu(self.menubar)
        self.menuTools.setObjectName("menuTools")
        self.menuHelp = QtWidgets.QMenu(self.menubar)
        self.menuHelp.setObjectName("menuHelp")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.toolBar = QtWidgets.QToolBar(MainWindow)
        self.toolBar.setMovable(False)
        self.toolBar.setObjectName("toolBar")
        MainWindow.addToolBar(QtCore.Qt.TopToolBarArea, self.toolBar)
        self.actionOpen = QtWidgets.QAction(MainWindow)
        self.actionOpen.setObjectName("actionOpen")
        self.actionExit = QtWidgets.QAction(MainWindow)
        self.actionExit.setObjectName("actionExit")
        self.actionSave = QtWidgets.QAction(MainWindow)
        self.actionSave.setObjectName("actionSave")
        self.actionSet = QtWidgets.QAction(MainWindow)
        self.actionSet.setShortcut("")
        self.actionSet.setObjectName("actionSet")
        self.actionStart = QtWidgets.QAction(MainWindow)
        self.actionStart.setObjectName("actionStart")
        self.actionStop = QtWidgets.QAction(MainWindow)
        self.actionStop.setShortcut("")
        self.actionStop.setObjectName("actionStop")
        self.actionRestart = QtWidgets.QAction(MainWindow)
        self.actionRestart.setObjectName("actionRestart")
        self.actionGoto = QtWidgets.QAction(MainWindow)
        self.actionGoto.setObjectName("actionGoto")
        self.actionAbove = QtWidgets.QAction(MainWindow)
        self.actionAbove.setWhatsThis("")
        self.actionAbove.setObjectName("actionAbove")
        self.actionBelow = QtWidgets.QAction(MainWindow)
        self.actionBelow.setWhatsThis("")
        self.actionBelow.setObjectName("actionBelow")
        self.actionFirst = QtWidgets.QAction(MainWindow)
        self.actionFirst.setWhatsThis("")
        self.actionFirst.setObjectName("actionFirst")
        self.actionLast = QtWidgets.QAction(MainWindow)
        self.actionLast.setWhatsThis("")
        self.actionLast.setObjectName("actionLast")
        self.actionSave_2 = QtWidgets.QAction(MainWindow)
        self.actionSave_2.setObjectName("actionSave_2")
        self.actionFilter = QtWidgets.QAction(MainWindow)
        self.actionFilter.setObjectName("actionFilter")
        self.actionTCP = QtWidgets.QAction(MainWindow)
        self.actionTCP.setObjectName("actionTCP")
        self.actionUDP = QtWidgets.QAction(MainWindow)
        self.actionUDP.setObjectName("actionUDP")
        self.actionICMP = QtWidgets.QAction(MainWindow)
        self.actionICMP.setObjectName("actionICMP")
        self.actionARP = QtWidgets.QAction(MainWindow)
        self.actionARP.setObjectName("actionARP")
        self.actionHTTP = QtWidgets.QAction(MainWindow)
        self.actionHTTP.setObjectName("actionHTTP")
        self.actionHTTPS = QtWidgets.QAction(MainWindow)
        self.actionHTTPS.setObjectName("actionHTTPS")
        self.actionFTP = QtWidgets.QAction(MainWindow)
        self.actionFTP.setObjectName("actionFTP")
        self.actionTELNET = QtWidgets.QAction(MainWindow)
        self.actionTELNET.setObjectName("actionTELNET")
        self.actionIPv4 = QtWidgets.QAction(MainWindow)
        self.actionIPv4.setObjectName("actionIPv4")
        self.actionIPv6 = QtWidgets.QAction(MainWindow)
        self.actionIPv6.setObjectName("actionIPv6")
        self.actionSendUDP = QtWidgets.QAction(MainWindow)
        self.actionSendUDP.setWhatsThis("")
        self.actionSendUDP.setObjectName("actionSendUDP")
        self.actionSendTCP = QtWidgets.QAction(MainWindow)
        self.actionSendTCP.setWhatsThis("")
        self.actionSendTCP.setObjectName("actionSendTCP")
        self.actionSendICMP = QtWidgets.QAction(MainWindow)
        self.actionSendICMP.setWhatsThis("")
        self.actionSendICMP.setObjectName("actionSendICMP")
        self.actionDoc = QtWidgets.QAction(MainWindow)
        self.actionDoc.setObjectName("actionDoc")
        self.actionInfo = QtWidgets.QAction(MainWindow)
        self.actionInfo.setObjectName("actionInfo")
        self.actionStart2 = QtWidgets.QAction(MainWindow)
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap("icon/start.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionStart2.setIcon(icon1)
        self.actionStart2.setObjectName("actionStart2")
        self.actionStop2 = QtWidgets.QAction(MainWindow)
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap("icon/stop.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionStop2.setIcon(icon2)
        self.actionStop2.setObjectName("actionStop2")
        self.actionRestart2 = QtWidgets.QAction(MainWindow)
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap("icon/restart.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionRestart2.setIcon(icon3)
        self.actionRestart2.setObjectName("actionRestart2")
        self.actionSave2 = QtWidgets.QAction(MainWindow)
        icon4 = QtGui.QIcon()
        icon4.addPixmap(QtGui.QPixmap("icon/save.png"), QtGui.QIcon.Normal, QtGui.QIcon.On)
        self.actionSave2.setIcon(icon4)
        self.actionSave2.setObjectName("actionSave2")
        self.actionGoto2 = QtWidgets.QAction(MainWindow)
        icon5 = QtGui.QIcon()
        icon5.addPixmap(QtGui.QPixmap("icon/goto.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionGoto2.setIcon(icon5)
        self.actionGoto2.setObjectName("actionGoto2")
        self.actionAbove2 = QtWidgets.QAction(MainWindow)
        icon6 = QtGui.QIcon()
        icon6.addPixmap(QtGui.QPixmap("icon/above.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionAbove2.setIcon(icon6)
        self.actionAbove2.setWhatsThis("")
        self.actionAbove2.setObjectName("actionAbove2")
        self.actionBelow2 = QtWidgets.QAction(MainWindow)
        icon7 = QtGui.QIcon()
        icon7.addPixmap(QtGui.QPixmap("icon/below.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionBelow2.setIcon(icon7)
        self.actionBelow2.setWhatsThis("")
        self.actionBelow2.setObjectName("actionBelow2")
        self.menuFile.addAction(self.actionOpen)
        self.menuFile.addSeparator()
        self.menuFile.addAction(self.actionSave)
        self.menuFile.addAction(self.actionExit)
        self.menuGoto.addAction(self.actionGoto)
        self.menuGoto.addAction(self.actionAbove)
        self.menuGoto.addAction(self.actionBelow)
        self.menuGoto.addAction(self.actionFirst)
        self.menuGoto.addAction(self.actionLast)
        self.menuSniff.addAction(self.actionSet)
        self.menuSniff.addSeparator()
        self.menuSniff.addAction(self.actionStart)
        self.menuSniff.addAction(self.actionStop)
        self.menuSniff.addAction(self.actionRestart)
        self.menuQuickFilter.addAction(self.actionTCP)
        self.menuQuickFilter.addAction(self.actionUDP)
        self.menuQuickFilter.addAction(self.actionICMP)
        self.menuQuickFilter.addAction(self.actionARP)
        self.menuQuickFilter.addAction(self.actionHTTP)
        self.menuQuickFilter.addAction(self.actionHTTPS)
        self.menuQuickFilter.addAction(self.actionFTP)
        self.menuQuickFilter.addAction(self.actionTELNET)
        self.menuQuickFilter.addAction(self.actionIPv4)
        self.menuQuickFilter.addAction(self.actionIPv6)
        self.menuAnalyze.addAction(self.actionFilter)
        self.menuAnalyze.addAction(self.menuQuickFilter.menuAction())
        self.menuTools.addAction(self.actionSendUDP)
        self.menuTools.addAction(self.actionSendTCP)
        self.menuTools.addAction(self.actionSendICMP)
        self.menuHelp.addAction(self.actionDoc)
        self.menuHelp.addAction(self.actionInfo)
        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuSniff.menuAction())
        self.menubar.addAction(self.menuGoto.menuAction())
        self.menubar.addAction(self.menuAnalyze.menuAction())
        self.menubar.addAction(self.menuTools.menuAction())
        self.menubar.addAction(self.menuHelp.menuAction())
        self.toolBar.addAction(self.actionStart2)
        self.toolBar.addAction(self.actionStop2)
        self.toolBar.addAction(self.actionRestart2)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.actionSave2)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.actionGoto2)
        self.toolBar.addAction(self.actionAbove2)
        self.toolBar.addAction(self.actionBelow2)

        self.actionStop2.setDisabled(True)
        self.actionRestart2.setDisabled(True)
        self.actionStop.setDisabled(True)
        self.actionRestart.setDisabled(True)

        self.retranslateUi(MainWindow)
        self.QuickFilterComboBox.currentIndexChanged.connect(MainWindow.actionchoose)
        self.FilterButton.clicked.connect(MainWindow.actioncondi)
        #self.FilterEdit.returnPressed.connect(MainWindow.actioncondi)
        self.actionExit.triggered.connect(MainWindow.close)
        self.actionStart.triggered.connect(MainWindow.beginSniff)
        self.actionStop.triggered.connect(MainWindow.pauseSniff)
        self.actionRestart.triggered.connect(MainWindow.restartSniff)
        self.actionStart2.triggered.connect(MainWindow.beginSniff)
        self.actionStop2.triggered.connect(MainWindow.pauseSniff)
        self.actionRestart2.triggered.connect(MainWindow.restartSniff)
        self.actionTCP.triggered.connect(lambda:MainWindow.screen("TCP"))
        self.actionUDP.triggered.connect(lambda:MainWindow.screen("UDP"))
        self.actionICMP.triggered.connect(lambda:MainWindow.screen("ICMP"))
        self.actionARP.triggered.connect(lambda:MainWindow.screen("ARP"))
        self.actionHTTP.triggered.connect(lambda:MainWindow.screen("Http"))
        self.actionHTTPS.triggered.connect(lambda:MainWindow.screen("Https"))
        self.actionFTP.triggered.connect(lambda:MainWindow.screen("FTP"))
        self.actionTELNET.triggered.connect(lambda:MainWindow.screen("TELNET"))
        self.actionIPv4.triggered.connect(lambda:MainWindow.screen("IPv4"))
        self.actionIPv6.triggered.connect(lambda:MainWindow.screen("IPv6"))
        self.actionSave.triggered.connect(MainWindow.save)
        self.actionOpen.triggered.connect(MainWindow.open)
        self.actionAbove.triggered.connect(MainWindow.above)
        self.actionBelow.triggered.connect(MainWindow.below)
        self.actionFirst.triggered.connect(MainWindow.first)
        self.actionLast.triggered.connect(MainWindow.last)
        self.tableView.clicked.connect(MainWindow.click)
        self.actionAbove2.triggered.connect(MainWindow.above)
        self.actionBelow2.triggered.connect(MainWindow.below)

        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "WhaleTrace"))
        self.FilterEdit.setStatusTip(_translate("MainWindow", "应用显示过滤器..."))
        self.FilterEdit.setPlaceholderText(_translate("MainWindow", "应用显示过滤器..."))
        self.QuickFilterComboBox.setStatusTip(_translate("MainWindow", "快速过滤"))
        self.FilterButton.setText(_translate("MainWindow", "确定"))
        self.menuFile.setTitle(_translate("MainWindow", "文件"))
        self.menuGoto.setTitle(_translate("MainWindow", "跳转"))
        self.menuSniff.setTitle(_translate("MainWindow", "捕获"))
        self.menuAnalyze.setTitle(_translate("MainWindow", "分析"))
        self.menuQuickFilter.setTitle(_translate("MainWindow", "快速过滤"))
        self.menuTools.setTitle(_translate("MainWindow", "工具"))
        self.menuHelp.setTitle(_translate("MainWindow", "帮助"))
        self.toolBar.setWindowTitle(_translate("MainWindow", "toolBar"))
        self.actionOpen.setText(_translate("MainWindow", "打开"))
        self.actionOpen.setStatusTip(_translate("MainWindow", "打开文件"))
        self.actionOpen.setShortcut(_translate("MainWindow", "Ctrl+O"))
        self.actionExit.setText(_translate("MainWindow", "退出"))
        self.actionExit.setStatusTip(_translate("MainWindow", "退出WhaleTrace"))
        self.actionExit.setShortcut(_translate("MainWindow", "Ctrl+Q"))
        self.actionSave.setText(_translate("MainWindow", "保存"))
        self.actionSave.setStatusTip(_translate("MainWindow", "保存当前文件"))
        self.actionSave.setShortcut(_translate("MainWindow", "Ctrl+S"))
        self.actionSet.setText(_translate("MainWindow", "设置"))
        self.actionSet.setStatusTip(_translate("MainWindow", "设置"))
        self.actionStart.setText(_translate("MainWindow", "开始"))
        self.actionStart.setStatusTip(_translate("MainWindow", "开始捕获"))
        self.actionStart.setShortcut(_translate("MainWindow", "Ctrl+E"))
        self.actionStop.setText(_translate("MainWindow", "停止"))
        self.actionStop.setStatusTip(_translate("MainWindow", "停止捕获"))
        self.actionRestart.setText(_translate("MainWindow", "重新开始"))
        self.actionRestart.setStatusTip(_translate("MainWindow", "重新开始捕获"))
        self.actionRestart.setShortcut(_translate("MainWindow", "Ctrl+R"))
        self.actionGoto.setText(_translate("MainWindow", "转至分组"))
        self.actionGoto.setStatusTip(_translate("MainWindow", "跳转到指定分组"))
        self.actionGoto.setWhatsThis(_translate("MainWindow", "跳转到指定分组"))
        self.actionGoto.setShortcut(_translate("MainWindow", "Ctrl+G"))
        self.actionAbove.setText(_translate("MainWindow", "上一个分组"))
        self.actionAbove.setStatusTip(_translate("MainWindow", "跳转至上一个分组"))
        self.actionAbove.setShortcut(_translate("MainWindow", "Ctrl+Up"))
        self.actionBelow.setText(_translate("MainWindow", "下一个分组"))
        self.actionBelow.setStatusTip(_translate("MainWindow", "跳转至下一个分组"))
        self.actionBelow.setShortcut(_translate("MainWindow", "Ctrl+Down"))
        self.actionFirst.setText(_translate("MainWindow", "首个分组"))
        self.actionFirst.setStatusTip(_translate("MainWindow", "跳转至第一个分组"))
        self.actionLast.setText(_translate("MainWindow", "最新分组"))
        self.actionLast.setStatusTip(_translate("MainWindow", "跳转至最后一个分组"))
        self.actionSave_2.setText(_translate("MainWindow", "baocun "))
        self.actionFilter.setText(_translate("MainWindow", "显示过滤器"))
        self.actionFilter.setStatusTip(_translate("MainWindow", "显示过滤器"))
        self.actionTCP.setText(_translate("MainWindow", "TCP"))
        self.actionUDP.setText(_translate("MainWindow", "UDP"))
        self.actionICMP.setText(_translate("MainWindow", "ICMP"))
        self.actionARP.setText(_translate("MainWindow", "ARP"))
        self.actionHTTP.setText(_translate("MainWindow", "HTTP"))
        self.actionHTTPS.setText(_translate("MainWindow", "HTTPS"))
        self.actionFTP.setText(_translate("MainWindow", "FTP"))
        self.actionTELNET.setText(_translate("MainWindow", "TELNET"))
        self.actionIPv4.setText(_translate("MainWindow", "IPv4"))
        self.actionIPv6.setText(_translate("MainWindow", "IPv6"))
        self.actionSendUDP.setText(_translate("MainWindow", "发送UDP包"))
        self.actionSendUDP.setStatusTip(_translate("MainWindow", "发送UDP包"))
        self.actionSendTCP.setText(_translate("MainWindow", "发送TCP包"))
        self.actionSendTCP.setStatusTip(_translate("MainWindow", "发送TCP包"))
        self.actionSendICMP.setText(_translate("MainWindow", "发送ICMP包"))
        self.actionSendICMP.setStatusTip(_translate("MainWindow", "发送ICMP包"))
        self.actionDoc.setText(_translate("MainWindow", "说明文档"))
        self.actionDoc.setStatusTip(_translate("MainWindow", "打开说明文档"))
        self.actionDoc.setShortcut(_translate("MainWindow", "F1"))
        self.actionInfo.setText(_translate("MainWindow", "关于"))
        self.actionInfo.setStatusTip(_translate("MainWindow", "关于WhaleTrace"))
        self.actionStart2.setText(_translate("MainWindow", "开始"))
        self.actionStart2.setStatusTip(_translate("MainWindow", "开始嗅探"))
        self.actionStop2.setText(_translate("MainWindow", "停止"))
        self.actionStop2.setStatusTip(_translate("MainWindow", "停止嗅探"))
        self.actionRestart2.setText(_translate("MainWindow", "重新开始"))
        self.actionRestart2.setStatusTip(_translate("MainWindow", "重新开始嗅探"))
        self.actionSave2.setText(_translate("MainWindow", "保存"))
        self.actionSave2.setStatusTip(_translate("MainWindow", "保存当前文件"))
        self.actionGoto2.setText(_translate("MainWindow", "转到分组"))
        self.actionGoto2.setStatusTip(_translate("MainWindow", "转到分组"))
        self.actionAbove2.setText(_translate("MainWindow", "上一个分组"))
        self.actionAbove2.setStatusTip(_translate("MainWindow", "跳转至上一个分组"))
        self.actionAbove2.setShortcut(_translate("MainWindow", "Ctrl+Up"))
        self.actionBelow2.setText(_translate("MainWindow", "下一个分组"))
        self.actionBelow2.setStatusTip(_translate("MainWindow", "跳转至下一个分组"))
        self.actionBelow2.setShortcut(_translate("MainWindow", "Ctrl+Down"))
