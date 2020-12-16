# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'analyze.ui'
#
# Created by: PyQt5 UI code generator 5.15.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Analyze(object):
    def setupUi(self, Analyze):
        Analyze.setObjectName("Analyze")
        Analyze.resize(1277, 916)
        self.centralwidget = QtWidgets.QWidget(Analyze)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setContentsMargins(5, 5, 5, 5)
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_6.addItem(spacerItem)
        self.logo = QtWidgets.QLabel(self.centralwidget)
        self.logo.setMinimumSize(QtCore.QSize(251, 81))
        self.logo.setMaximumSize(QtCore.QSize(251, 81))
        self.logo.setText("")
        self.logo.setPixmap(QtGui.QPixmap("static/logo_analyze.png"))
        self.logo.setScaledContents(True)
        self.logo.setAlignment(QtCore.Qt.AlignCenter)
        self.logo.setObjectName("logo")
        self.horizontalLayout_6.addWidget(self.logo)
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_6.addItem(spacerItem1)
        self.verticalLayout_3.addLayout(self.horizontalLayout_6)
        self.horizontalLayout_7 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setContentsMargins(5, 5, 5, 5)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label_7 = QtWidgets.QLabel(self.centralwidget)
        self.label_7.setMinimumSize(QtCore.QSize(60, 30))
        self.label_7.setAlignment(QtCore.Qt.AlignCenter)
        self.label_7.setObjectName("label_7")
        self.horizontalLayout.addWidget(self.label_7)
        self.filter_input = QtWidgets.QLineEdit(self.centralwidget)
        self.filter_input.setMinimumSize(QtCore.QSize(981, 30))
        self.filter_input.setEchoMode(QtWidgets.QLineEdit.Normal)
        self.filter_input.setObjectName("filter_input")
        self.horizontalLayout.addWidget(self.filter_input)
        spacerItem2 = QtWidgets.QSpacerItem(23, 23, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem2)
        self.go = QtWidgets.QPushButton(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.go.sizePolicy().hasHeightForWidth())
        self.go.setSizePolicy(sizePolicy)
        self.go.setMinimumSize(QtCore.QSize(30, 30))
        self.go.setObjectName("go")
        self.horizontalLayout.addWidget(self.go)
        self.horizontalLayout_7.addLayout(self.horizontalLayout)
        spacerItem3 = QtWidgets.QSpacerItem(18, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_7.addItem(spacerItem3)
        self.verticalLayout_3.addLayout(self.horizontalLayout_7)
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.pkt_list = QtWidgets.QListView(self.centralwidget)
        self.pkt_list.setMinimumSize(QtCore.QSize(331, 691))
        self.pkt_list.setObjectName("pkt_list")
        self.horizontalLayout_5.addWidget(self.pkt_list)
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setContentsMargins(10, 10, 10, 10)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setMinimumSize(QtCore.QSize(801, 31))
        self.label_3.setAlignment(QtCore.Qt.AlignCenter)
        self.label_3.setObjectName("label_3")
        self.verticalLayout_2.addWidget(self.label_3)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setContentsMargins(5, 5, 5, 5)
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.scrollArea = QtWidgets.QScrollArea(self.centralwidget)
        self.scrollArea.setMinimumSize(QtCore.QSize(551, 231))
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setObjectName("scrollArea")
        self.scrollAreaWidgetContents = QtWidgets.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 549, 244))
        self.scrollAreaWidgetContents.setObjectName("scrollAreaWidgetContents")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.scrollAreaWidgetContents)
        self.verticalLayout.setObjectName("verticalLayout")
        self.summary = QtWidgets.QLabel(self.scrollAreaWidgetContents)
        self.summary.setMinimumSize(QtCore.QSize(500, 220))
        self.summary.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.summary.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignTop)
        self.summary.setWordWrap(True)
        self.summary.setObjectName("summary")
        self.verticalLayout.addWidget(self.summary)
        self.scrollArea.setWidget(self.scrollAreaWidgetContents)
        self.horizontalLayout_4.addWidget(self.scrollArea)
        self.scrollArea_2 = QtWidgets.QScrollArea(self.centralwidget)
        self.scrollArea_2.setWidgetResizable(True)
        self.scrollArea_2.setObjectName("scrollArea_2")
        self.scrollAreaWidgetContents_2 = QtWidgets.QWidget()
        self.scrollAreaWidgetContents_2.setGeometry(QtCore.QRect(0, 0, 255, 230))
        self.scrollAreaWidgetContents_2.setObjectName("scrollAreaWidgetContents_2")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.scrollAreaWidgetContents_2)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.workbench = QtWidgets.QLabel(self.scrollAreaWidgetContents_2)
        self.workbench.setMinimumSize(QtCore.QSize(231, 200))
        self.workbench.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignTop)
        self.workbench.setWordWrap(True)
        self.workbench.setObjectName("workbench")
        self.verticalLayout_4.addWidget(self.workbench)
        self.scrollArea_2.setWidget(self.scrollAreaWidgetContents_2)
        self.horizontalLayout_4.addWidget(self.scrollArea_2)
        self.verticalLayout_2.addLayout(self.horizontalLayout_4)
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setMinimumSize(QtCore.QSize(811, 30))
        self.label_2.setAlignment(QtCore.Qt.AlignCenter)
        self.label_2.setObjectName("label_2")
        self.verticalLayout_2.addWidget(self.label_2)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setContentsMargins(5, 5, 5, 5)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.HexTextEdit = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.HexTextEdit.setMinimumSize(QtCore.QSize(541, 280))
        self.HexTextEdit.setCenterOnScroll(False)
        self.HexTextEdit.setObjectName("HexTextEdit")
        self.horizontalLayout_2.addWidget(self.HexTextEdit)
        self.AsciiTextEdit = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.AsciiTextEdit.setMinimumSize(QtCore.QSize(248, 280))
        self.AsciiTextEdit.setTabChangesFocus(False)
        self.AsciiTextEdit.setObjectName("AsciiTextEdit")
        self.horizontalLayout_2.addWidget(self.AsciiTextEdit)
        self.verticalLayout_2.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setContentsMargins(5, 5, 5, 5)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setMinimumSize(QtCore.QSize(113, 41))
        self.pushButton.setObjectName("pushButton")
        self.horizontalLayout_3.addWidget(self.pushButton)
        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setMinimumSize(QtCore.QSize(113, 41))
        self.pushButton_2.setObjectName("pushButton_2")
        self.horizontalLayout_3.addWidget(self.pushButton_2)
        self.pushButton_3 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_3.setMinimumSize(QtCore.QSize(113, 41))
        self.pushButton_3.setObjectName("pushButton_3")
        self.horizontalLayout_3.addWidget(self.pushButton_3)
        self.pushButton_4 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_4.setMinimumSize(QtCore.QSize(113, 41))
        self.pushButton_4.setObjectName("pushButton_4")
        self.horizontalLayout_3.addWidget(self.pushButton_4)
        spacerItem4 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem4)
        self.verticalLayout_2.addLayout(self.horizontalLayout_3)
        self.horizontalLayout_5.addLayout(self.verticalLayout_2)
        self.verticalLayout_3.addLayout(self.horizontalLayout_5)
        Analyze.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(Analyze)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1277, 22))
        self.menubar.setObjectName("menubar")
        self.menuFile = QtWidgets.QMenu(self.menubar)
        self.menuFile.setObjectName("menuFile")
        self.menuTools = QtWidgets.QMenu(self.menubar)
        self.menuTools.setObjectName("menuTools")
        self.menuHelp = QtWidgets.QMenu(self.menubar)
        self.menuHelp.setObjectName("menuHelp")
        Analyze.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(Analyze)
        self.statusbar.setObjectName("statusbar")
        Analyze.setStatusBar(self.statusbar)
        self.actionOpen = QtWidgets.QAction(Analyze)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("static/open.jpg"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionOpen.setIcon(icon)
        font = QtGui.QFont()
        font.setPointSize(15)
        self.actionOpen.setFont(font)
        self.actionOpen.setObjectName("actionOpen")
        self.actionExit = QtWidgets.QAction(Analyze)
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap("static/exit2.jpg"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionExit.setIcon(icon1)
        self.actionExit.setObjectName("actionExit")
        self.actionSave = QtWidgets.QAction(Analyze)
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap("static/save.jpg"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionSave.setIcon(icon2)
        self.actionSave.setObjectName("actionSave")
        self.actionSave_to = QtWidgets.QAction(Analyze)
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap("static/saveto.jpg"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionSave_to.setIcon(icon3)
        self.actionSave_to.setObjectName("actionSave_to")
        self.actionSearch = QtWidgets.QAction(Analyze)
        icon4 = QtGui.QIcon()
        icon4.addPixmap(QtGui.QPixmap("static/search.jpg"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionSearch.setIcon(icon4)
        self.actionSearch.setObjectName("actionSearch")
        self.actionDocs = QtWidgets.QAction(Analyze)
        icon5 = QtGui.QIcon()
        icon5.addPixmap(QtGui.QPixmap("static/doc.jpg"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.actionDocs.setIcon(icon5)
        self.actionDocs.setObjectName("actionDocs")
        self.menuFile.addAction(self.actionOpen)
        self.menuFile.addAction(self.actionSave)
        self.menuFile.addAction(self.actionSave_to)
        self.menuFile.addSeparator()
        self.menuFile.addAction(self.actionExit)
        self.menuTools.addAction(self.actionSearch)
        self.menuHelp.addAction(self.actionDocs)
        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuTools.menuAction())
        self.menubar.addAction(self.menuHelp.menuAction())

        self.retranslateUi(Analyze)
        self.go.clicked.connect(Analyze.go_on_clicked)
        self.pkt_list.clicked['QModelIndex'].connect(Analyze.item_on_clicked)
        self.HexTextEdit.textChanged.connect(Analyze.hex_changed)
        self.AsciiTextEdit.textChanged.connect(Analyze.ascii_changed)
        self.pushButton.clicked.connect(Analyze.save_on_clicked)
        self.pushButton_2.clicked.connect(Analyze.recover_on_clicked)
        self.pushButton_3.clicked.connect(Analyze.send_on_clicked)
        self.pushButton_4.clicked.connect(Analyze.more_on_clicked)
        self.actionOpen.triggered.connect(Analyze.open_triggered)
        self.actionSave.triggered.connect(Analyze.save_triggered)
        QtCore.QMetaObject.connectSlotsByName(Analyze)

        self.pushButton_4.setVisible(False)

    def retranslateUi(self, Analyze):
        _translate = QtCore.QCoreApplication.translate
        Analyze.setWindowTitle(_translate("Analyze", "MainWindow"))
        self.label_7.setText(_translate("Analyze", "Filter:"))
        self.filter_input.setPlaceholderText(_translate("Analyze", "请输入合法的BPF语言"))
        self.go.setText(_translate("Analyze", "GO"))
        self.label_3.setText(_translate("Analyze", "----Original packet----"))
        self.summary.setText(_translate("Analyze", "summary"))
        self.workbench.setText(_translate("Analyze", "workbench"))
        self.label_2.setText(_translate("Analyze", "----Packet_Editor----"))
        self.HexTextEdit.setPlaceholderText(_translate("Analyze", "hex"))
        self.AsciiTextEdit.setPlaceholderText(_translate("Analyze", "ascii"))
        self.pushButton.setText(_translate("Analyze", "Save"))
        self.pushButton_2.setText(_translate("Analyze", "Recover"))
        self.pushButton_3.setText(_translate("Analyze", "Send"))
        self.pushButton_4.setText(_translate("Analyze", "备用"))
        self.menuFile.setTitle(_translate("Analyze", "File"))
        self.menuTools.setTitle(_translate("Analyze", "Tools"))
        self.menuHelp.setTitle(_translate("Analyze", "Help"))
        self.actionOpen.setText(_translate("Analyze", "  Open"))
        self.actionExit.setText(_translate("Analyze", "  Exit"))
        self.actionSave.setText(_translate("Analyze", "  Save"))
        self.actionSave_to.setText(_translate("Analyze", "  Save to"))
        self.actionSearch.setText(_translate("Analyze", "  Search"))
        self.actionDocs.setText(_translate("Analyze", "Docs"))