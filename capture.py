# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'capture.ui'
#
# Created by: PyQt5 UI code generator 5.15.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Capture(object):
    def setupUi(self, Capture):
        Capture.setObjectName("Capture")
        Capture.resize(1536, 864)
        Capture.setMinimumSize(QtCore.QSize(1536, 864))
        self.centralwidget = QtWidgets.QWidget(Capture)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.all_layout = QtWidgets.QVBoxLayout()
        self.all_layout.setObjectName("all_layout")
        self.header_layout = QtWidgets.QHBoxLayout()
        self.header_layout.setObjectName("header_layout")
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.header_layout.addItem(spacerItem)
        self.logo = QtWidgets.QLabel(self.centralwidget)
        self.logo.setMinimumSize(QtCore.QSize(200, 80))
        self.logo.setAlignment(QtCore.Qt.AlignCenter)
        self.logo.setObjectName("logo")
        self.header_layout.addWidget(self.logo)
        spacerItem1 = QtWidgets.QSpacerItem(43, 23, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.header_layout.addItem(spacerItem1)
        self.all_layout.addLayout(self.header_layout)
        self.filter_layout = QtWidgets.QHBoxLayout()
        self.filter_layout.setObjectName("filter_layout")
        spacerItem2 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.filter_layout.addItem(spacerItem2)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label_7 = QtWidgets.QLabel(self.centralwidget)
        self.label_7.setMinimumSize(QtCore.QSize(60, 30))
        self.label_7.setAlignment(QtCore.Qt.AlignCenter)
        self.label_7.setObjectName("label_7")
        self.horizontalLayout.addWidget(self.label_7)
        self.filter = QtWidgets.QLineEdit(self.centralwidget)
        self.filter.setMinimumSize(QtCore.QSize(981, 30))
        self.filter.setEchoMode(QtWidgets.QLineEdit.Normal)
        self.filter.setObjectName("filter")
        self.horizontalLayout.addWidget(self.filter)
        spacerItem3 = QtWidgets.QSpacerItem(23, 23, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem3)
        self.go = QtWidgets.QPushButton(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.go.sizePolicy().hasHeightForWidth())
        self.go.setSizePolicy(sizePolicy)
        self.go.setMinimumSize(QtCore.QSize(30, 30))
        self.go.setObjectName("go")
        self.horizontalLayout.addWidget(self.go)
        self.filter_layout.addLayout(self.horizontalLayout)
        spacerItem4 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.filter_layout.addItem(spacerItem4)
        self.all_layout.addLayout(self.filter_layout)
        self.opration_layout = QtWidgets.QHBoxLayout()
        self.opration_layout.setContentsMargins(10, 10, 10, 10)
        self.opration_layout.setObjectName("opration_layout")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.gridLayout = QtWidgets.QGridLayout()
        self.gridLayout.setContentsMargins(10, 10, 10, 10)
        self.gridLayout.setObjectName("gridLayout")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setMinimumSize(QtCore.QSize(100, 30))
        self.label_2.setAlignment(QtCore.Qt.AlignCenter)
        self.label_2.setObjectName("label_2")
        self.gridLayout.addWidget(self.label_2, 0, 0, 1, 2)
        self.password = QtWidgets.QLineEdit(self.centralwidget)
        self.password.setMinimumSize(QtCore.QSize(150, 30))
        self.password.setObjectName("password")
        self.gridLayout.addWidget(self.password, 0, 2, 1, 2)
        self.label_4 = QtWidgets.QLabel(self.centralwidget)
        self.label_4.setMinimumSize(QtCore.QSize(100, 30))
        self.label_4.setAlignment(QtCore.Qt.AlignCenter)
        self.label_4.setObjectName("label_4")
        self.gridLayout.addWidget(self.label_4, 2, 0, 1, 2)
        self.session = QtWidgets.QLineEdit(self.centralwidget)
        self.session.setMinimumSize(QtCore.QSize(150, 30))
        self.session.setObjectName("session")
        self.gridLayout.addWidget(self.session, 2, 2, 1, 2)
        self.label_6 = QtWidgets.QLabel(self.centralwidget)
        self.label_6.setMinimumSize(QtCore.QSize(100, 30))
        self.label_6.setAlignment(QtCore.Qt.AlignCenter)
        self.label_6.setObjectName("label_6")
        self.gridLayout.addWidget(self.label_6, 4, 0, 1, 2)
        self.timeout = QtWidgets.QLineEdit(self.centralwidget)
        self.timeout.setMinimumSize(QtCore.QSize(150, 30))
        self.timeout.setObjectName("timeout")
        self.gridLayout.addWidget(self.timeout, 4, 2, 1, 2)
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setMinimumSize(QtCore.QSize(181, 51))
        self.pushButton.setObjectName("pushButton")
        self.gridLayout.addWidget(self.pushButton, 5, 0, 1, 4)
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setMinimumSize(QtCore.QSize(100, 30))
        self.label_3.setAlignment(QtCore.Qt.AlignCenter)
        self.label_3.setObjectName("label_3")
        self.gridLayout.addWidget(self.label_3, 1, 0, 1, 2)
        self.count = QtWidgets.QLineEdit(self.centralwidget)
        self.count.setMinimumSize(QtCore.QSize(150, 30))
        self.count.setObjectName("count")
        self.gridLayout.addWidget(self.count, 3, 2, 1, 2)
        self.label_5 = QtWidgets.QLabel(self.centralwidget)
        self.label_5.setMinimumSize(QtCore.QSize(100, 30))
        self.label_5.setAlignment(QtCore.Qt.AlignCenter)
        self.label_5.setObjectName("label_5")
        self.gridLayout.addWidget(self.label_5, 3, 0, 1, 2)
        self.iface = QtWidgets.QLineEdit(self.centralwidget)
        self.iface.setMinimumSize(QtCore.QSize(150, 30))
        self.iface.setObjectName("iface")
        self.gridLayout.addWidget(self.iface, 1, 2, 1, 2)
        self.verticalLayout_2.addLayout(self.gridLayout)
        spacerItem5 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout_2.addItem(spacerItem5)
        self.opration_layout.addLayout(self.verticalLayout_2)
        spacerItem6 = QtWidgets.QSpacerItem(18, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.opration_layout.addItem(spacerItem6)
        self.pkt_list = QtWidgets.QListView(self.centralwidget)
        self.pkt_list.setMinimumSize(QtCore.QSize(451, 601))
        self.pkt_list.setObjectName("pkt_list")
        self.opration_layout.addWidget(self.pkt_list)
        spacerItem7 = QtWidgets.QSpacerItem(18, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.opration_layout.addItem(spacerItem7)
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.output = QtWidgets.QLabel(self.centralwidget)
        self.output.setMinimumSize(QtCore.QSize(641, 161))
        self.output.setObjectName("output")
        self.verticalLayout.addWidget(self.output)
        spacerItem8 = QtWidgets.QSpacerItem(23, 23, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout.addItem(spacerItem8)
        self.graphicsView = QtWidgets.QGraphicsView(self.centralwidget)
        self.graphicsView.setMinimumSize(QtCore.QSize(641, 321))
        self.graphicsView.setObjectName("graphicsView")
        self.verticalLayout.addWidget(self.graphicsView)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setContentsMargins(10, 10, 10, 10)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setMinimumSize(QtCore.QSize(113, 50))
        self.pushButton_2.setObjectName("pushButton_2")
        self.horizontalLayout_2.addWidget(self.pushButton_2)
        self.pushButton_3 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_3.setMinimumSize(QtCore.QSize(113, 50))
        self.pushButton_3.setObjectName("pushButton_3")
        self.horizontalLayout_2.addWidget(self.pushButton_3)
        self.pushButton_4 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_4.setMinimumSize(QtCore.QSize(113, 50))
        self.pushButton_4.setObjectName("pushButton_4")
        self.horizontalLayout_2.addWidget(self.pushButton_4)
        self.pushButton_5 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_5.setMinimumSize(QtCore.QSize(113, 50))
        self.pushButton_5.setObjectName("pushButton_5")
        self.horizontalLayout_2.addWidget(self.pushButton_5)
        self.horizontalLayout_3.addLayout(self.horizontalLayout_2)
        spacerItem9 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem9)
        self.verticalLayout.addLayout(self.horizontalLayout_3)
        self.opration_layout.addLayout(self.verticalLayout)
        self.all_layout.addLayout(self.opration_layout)
        self.terminal_layout = QtWidgets.QHBoxLayout()
        self.terminal_layout.setContentsMargins(5, 5, 5, 5)
        self.terminal_layout.setObjectName("terminal_layout")
        self.feedback = QtWidgets.QLabel(self.centralwidget)
        self.feedback.setMinimumSize(QtCore.QSize(1111, 30))
        self.feedback.setObjectName("feedback")
        self.terminal_layout.addWidget(self.feedback)
        self.feedback_2 = QtWidgets.QLabel(self.centralwidget)
        self.feedback_2.setMinimumSize(QtCore.QSize(341, 30))
        self.feedback_2.setObjectName("feedback_2")
        self.terminal_layout.addWidget(self.feedback_2)
        self.all_layout.addLayout(self.terminal_layout)
        self.verticalLayout_4.addLayout(self.all_layout)
        Capture.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(Capture)
        self.statusbar.setObjectName("statusbar")
        Capture.setStatusBar(self.statusbar)

        self.retranslateUi(Capture)
        self.go.clicked.connect(Capture.start_on_clicked)
        self.pushButton.clicked.connect(Capture.start_on_clicked)
        self.pushButton_2.clicked.connect(Capture.zoom_in_on_clicked)
        self.pushButton_3.clicked.connect(Capture.zoom_out_on_clicked)
        self.pushButton_4.clicked.connect(Capture.save_graph_on_clicked)
        self.pushButton_5.clicked.connect(Capture.save_pcap_on_clicked)
        self.filter.textChanged['QString'].connect(Capture.text_changed)
        self.pkt_list.doubleClicked['QModelIndex'].connect(Capture.pkts_double_clicked)
        self.pkt_list.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        QtCore.QMetaObject.connectSlotsByName(Capture)

    def retranslateUi(self, Capture):
        _translate = QtCore.QCoreApplication.translate
        Capture.setWindowTitle(_translate("Capture", "MainWindow"))
        self.logo.setText(_translate("Capture", "logo"))
        self.label_7.setText(_translate("Capture", "Filter:"))
        self.filter.setPlaceholderText(_translate("Capture", "请输入合法的BPF语言"))
        self.iface.setPlaceholderText(_translate("Capture", "en0"))
        self.session.setPlaceholderText(_translate("Capture", "TCPSession"))
        self.count.setPlaceholderText(_translate("Capture", "0"))
        self.timeout.setPlaceholderText(_translate("Capture", "5"))
        self.go.setText(_translate("Capture", "GO"))
        self.label_2.setText(_translate("Capture", "Password:"))
        self.label_4.setText(_translate("Capture", "Session:"))
        self.label_6.setText(_translate("Capture", "Timeout:"))
        self.pushButton.setText(_translate("Capture", "Start!"))
        self.label_3.setText(_translate("Capture", "iface:"))
        self.label_5.setText(_translate("Capture", "Count:"))
        self.output.setText(_translate("Capture", "总信息"))
        self.pushButton_2.setText(_translate("Capture", "Zoom in"))
        self.pushButton_3.setText(_translate("Capture", "Zoom out"))
        self.pushButton_4.setText(_translate("Capture", "Save graph"))
        self.pushButton_5.setText(_translate("Capture", "Save pcap"))
        self.feedback.setText(_translate("Capture", "feedback"))
        self.feedback_2.setText(_translate("Capture", "feedback"))
