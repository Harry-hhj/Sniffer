from PyQt5 import QtWidgets, QtCore
from PyQt5.QtGui import QImage, QPixmap, QFont, QPainter
from PyQt5.QtChart import QLineSeries, QValueAxis, QChartView

from entry import Ui_Entry
from capture import Ui_Capture
from detail import Ui_Detail
from analyze import Ui_Analyze
from TextDialog import Ui_TextDialog
from ListDialog import Ui_ListDialog
from Quick_Modify import Ui_Dialog as Ui_QMDialog
from monitor import Ui_Monitor
from Sniffer import Sniffer

from scapy.all import *
import numpy as np
import time
import os
import ctypes
import inspect


# show_interfaces()


def copy_file():
    from shutil import copyfile

    source = './tmp/test.jpg'
    target = './test.jpg'

    # adding exception handling
    try:
        copyfile(source, target)
    except IOError as e:
        print("Unable to copy file. %s" % e)
        return
    except:
        print("Unexpected error:", sys.exc_info())
        return

    print("\nFile copy to project path done!\n")


def find_diff(a, b):
    diff_index = np.array(list(a)) != np.array(list(b))
    return np.where(diff_index == True)[0].tolist()


# 时间戳转换函数
def TimeStamp2Time(timeStamp):
    timeTmp = time.localtime(timeStamp)  # time.localtime()格式化时间戳为本地时间
    myTime = time.strftime("%Y-%m-%d %H:%M:%S", timeTmp)  # 将本地时间格式化为字符串
    return myTime


def _async_raise(tid, exctype):
    """raises the exception, performs cleanup if needed"""
    tid = ctypes.c_long(tid)
    if not inspect.isclass(exctype):
        exctype = type(exctype)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, ctypes.py_object(exctype))
    if res == 0:
        raise ValueError("invalid thread id")
    elif res != 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")


def stop_thread(thread):
    _async_raise(thread.ident, SystemExit)


class MainWindow(QtWidgets.QMainWindow, Ui_Entry):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.setupUi(self)

    def capture_on_clicked(self):
        sub1.show()

    def analyze_on_clicked(self):
        sub2.show()

    def monitor_on_clicked(self):
        dialog = Monitor()
        dialog.exec()

    def exit_on_clicked(self):
        sys.exit()

    def closeEvent(self, event):
        sys.exit(0)


class SubWindow_capture(QtWidgets.QMainWindow, Ui_Capture):
    signal = QtCore.pyqtSignal()
    update_signal = QtCore.pyqtSignal(str)
    time_signal = QtCore.pyqtSignal(str)
    update_frame = QtCore.pyqtSignal()

    def __init__(self):
        super(SubWindow_capture, self).__init__()
        self.setupUi(self)
        self.summaries = []

        self.slm = QtCore.QStringListModel()  # 创建mode
        self.slm.setStringList(self.summaries)  # 将数据设置到model
        self.pkt_list.setModel(self.slm)  # 绑定 listView 和 model
        self.pushButton_8.setVisible(False)

        self.zoomscale = 1.0
        self.scene = QtWidgets.QGraphicsScene()  # 创建场景
        self.graphicsView.setScene(self.scene)  # 将场景添加至视图
        self.comboBox.addItems(['不进行整流', 'IPSession', 'TCPSession'])

        self.signal.connect(self.show_sessions)
        self.update_signal.connect(self.myupdate)
        self.time_signal.connect(self.update_time)
        self.update_frame.connect(self.add_pic)

        self.thread = None

        import psutil
        info = psutil.net_if_addrs()
        for k, _ in info.items():
            self.iface.addItem(k)

        thread = threading.Thread(target=self.timer, args=(self.time_signal,))
        thread.setDaemon(True)
        thread.start()

        self.feedback.setText('Ready to sniff.')

        self.feedback.setStyleSheet('''
                            border:none;
                            font-size:16px;
                            font-weight:700;
                            font-family: "Helvetica Neue", Helvetica, Arial;
                            color:green;
                        ''')

        self.feedback_2.setStyleSheet('''
                    border:none;
                    font-size:16px;
                    font-weight:700;
                    font-family: "Helvetica Neue", Helvetica, Arial;
                    color:blue;
                ''')

        self.output.setStyleSheet('''
                    border:none;
                    font-size:16px;
                    font-weight:700;
                    font-family: "Helvetica Neue", Helvetica, Arial;
                    color:gray;
                ''')

        self.pushButton.setStyleSheet('''
                    QPushButton{
                        border:none;
                        font-size:16px;
                        font-weight:bold;
                    }
                ''')

        self.pushButton_9.setStyleSheet('''
                    QPushButton{
                        border:none;
                        font-size:16px;
                        color:red;
                        font-weight:bold;
                    }
                ''')

        self.pushButton_6.setStyleSheet('''
                    QPushButton{
                        border:none;
                        border-radius:10px;
                        font-size:16px;
                        color:green;
                        padding-left:5px;
                        padding-right:10px;
                        text-align:hcenter;
                        background:LightBlue;
                    }
                    QPushButton:hover{
                        color:black;
                        border:1px solid #F3F3F5;
                        border-radius:10px;
                        background:LightGray;
                    }
                ''')

        self.pushButton_7.setStyleSheet('''
                    QPushButton{
                        border:none;
                        border-radius:10px;
                        font-size:16px;
                        color:green;
                        padding-left:5px;
                        padding-right:10px;
                        text-align:hcenter;
                        background:LightBlue;
                    }
                    QPushButton:hover{
                        color:black;
                        border:1px solid #F3F3F5;
                        border-radius:10px;
                        background:LightGray;
                    }
                ''')

        self.pushButton_8.setStyleSheet('''
                    QPushButton{
                        border:none;
                        border-radius:10px;
                        font-size:16px;
                        color:green;
                        padding-left:5px;
                        padding-right:10px;
                        text-align:hcenter;
                        background:LightBlue;
                    }
                    QPushButton:hover{
                        color:black;
                        border:1px solid #F3F3F5;
                        border-radius:10px;
                        background:LightGray;
                    }
                ''')

        self.pushButton_4.setStyleSheet('''
                    QPushButton{
                        border:none;
                        border-radius:10px;
                        font-size:16px;
                        padding-left:5px;
                        padding-right:10px;
                        text-align:hcenter;
                        background:LightGreen;
                    }
                    QPushButton:hover{
                        color:black;
                        border:1px solid #F3F3F5;
                        border-radius:10px;
                        background:LightGray;
                    }
                ''')

        self.pushButton_5.setStyleSheet('''
                    QPushButton{
                        border:none;
                        border-radius:10px;
                        font-size:16px;
                        padding-left:5px;
                        padding-right:10px;
                        text-align:hcenter;
                        background:LightGreen;
                    }
                    QPushButton:hover{
                        color:black;
                        border:1px solid #F3F3F5;
                        border-radius:10px;
                        background:LightGray;
                    }
                ''')

        self._last_update = time.time()
        self._back_status = False

        self.cnt = [0, 0, 0, 0]

    def myupdate(self, string):
        # self.summaries.append(string)
        # old_method
        # t = time.time()
        # if self.init_once:
        #     self._last_update = t
        #     self.init_once = False
        #     self.slm.setStringList(self.summaries)  # 将数据设置到model
        #     self.dpkts = PacketList(self.sniffer.dpkt_list)
        #     output = str(self.dpkts) + '\nExtract sessions from packets: ' + str(
        #         len(self.dpkts.sessions().keys())) + '.'
        #     self.output.setText(output)
        # elif t - self._last_update >= 0.5:
        #     self._last_update = t
        #     self.slm.setStringList(self.summaries)  # 将数据设置到model
        #     self.dpkts = self.dpkts + PacketList([self.sniffer.packet])
        #     self.dpkts.listname = 'PacketList'
        #     output = str(self.dpkts) + '\nExtract sessions from packets: ' + str(
        #         len(self.dpkts.sessions().keys())) + '.'
        #     self.output.setText(output)
        # self.slm.setStringList(self.summaries)  # 将数据设置到model
        t = time.time()
        if t - self._last_update >= 0.5:
            self._last_update = t
            for str in self.summaries:
                count = self.slm.rowCount()
                self.slm.insertRow(count)
                index = self.slm.index(count, 0)
                self.slm.setData(index, str, QtCore.Qt.DisplayRole)
            self.summaries.clear()
        else:
            self.summaries.append(string)
        if 'TCP' in string:
            self.cnt[0] += 1
        elif 'ICMP' in string:
            self.cnt[1] += 1
        elif 'UDP' in string:
            self.cnt[2] += 1
        else:
            self.cnt[3] += 1
        output = 'PacketList: <TCP: {}, ICMP: {}, UDP: {}, Other: {}>'.format(self.cnt[0], self.cnt[1],
                                                                              self.cnt[2], self.cnt[3])
        self.output.setText(output)

    def backRun(self, signal):
        try:
            self._back_status = True
            # iface = self.iface.text()
            # if iface == '':
            #     iface = 'en0'
            iface = self.iface.currentText()
            filter = self.filter.text()
            # session = self.session.text()
            session = self.comboBox.currentIndex()
            if session == 0:
                session = ''
            elif session == 1:
                session = 'IPSession'
            elif session == 2:
                session = 'TCPSession'
            else:
                session = ''
            count = 0 if self.count.text() == '' else eval(self.count.text())
            if self.timeout.text() == '':
                timeout = None
            else:
                timeout = eval(self.timeout.text())
            password = self.password.text()
            self.sniffer = Sniffer(iface=iface, filter=filter, session=session, count=count, timeout=timeout,
                                   prn=self.update_signal)
            self.sniffer.run()
            output = str(self.sniffer.dpkts) + '\nExtract sessions from packets: ' + str(
                len(self.sniffer.dpkts.sessions().keys())) + '.'
            for dpkt in self.sniffer.dpkts:
                summary = dpkt.summary()
                self.summaries.append(summary)
            self.slm.setStringList(self.summaries)  # 将数据设置到model
            self.output.setText(output)
            try:
                os.remove('tmp/test.jpg')
            except:
                pass
            self.sniffer.draw()
            self.feedback.setText("Sniff done.")
            # opencv图像
            # pix = QPixmap.fromImage(frame)
            # self.item = QGraphicsPixmapItem(pix)  # 创建像素图元
            # # self.item.setScale(self.zoomscale)
            # self.scene = QGraphicsScene()  # 创建场景
            # self.scene.addItem(self.item)
            # self.picshow.setScene(self.scene)  # 将场景添加至视图
            self.update_frame.emit()
            self._back_status = False
            signal.emit()
        except:
            pass

    def timer(self, signal):
        t_ = time.time()
        while True:
            t = time.time()
            if t - t_ >= 1:
                t_ = t
                signal.emit(TimeStamp2Time(t))

    def update_time(self, string):
        self.feedback_2.setText(string)

    def start_on_clicked(self):
        self.go.setVisible(False)
        self.summaries = []
        self.slm.setStringList(self.summaries)  # 将数据设置到model
        self.cnt = [0, 0, 0, 0]
        self.output.clear()
        self.feedback.setText("Begin to sniff........Please wait.")
        self.thread = threading.Thread(target=self.backRun, args=(self.signal,))
        self.thread.setDaemon(True)
        self.thread.start()

    def zoom_in_on_clicked(self):
        self.zoomscale = self.zoomscale + 0.05
        self.QGP_item.setScale(self.zoomscale)

    def zoom_out_on_clicked(self):
        self.zoomscale = self.zoomscale - 0.05
        if self.zoomscale <= 0:
            self.zoomscale = 0.2
        self.QGP_item.setScale(self.zoomscale)

    def save_pcap_on_clicked(self):
        self.sniffer.save()

    def save_graph_on_clicked(self):
        copy_file()

    def add_pic(self):
        pix = QPixmap('./tmp/test.jpg')
        self.QGP_item = QtWidgets.QGraphicsPixmapItem(pix)  # 创建像素图元
        self.scene.clear()
        self.scene.addItem(self.QGP_item)

    def text_changed(self):
        # 没有语法检查器，所以不实现自动检测输入变化
        pass

    def pkts_double_clicked(self):
        if not self._back_status:
            idx = self.pkt_list.currentIndex().row()  # 这个值就是所选的列表值
            tmp = self.sniffer.dpkts[idx]
            dialog = DetailDialog(tmp)
            dialog.exec()
        else:
            idx = self.pkt_list.currentIndex().row()  # 这个值就是所选的列表值
            tmp = self.sniffer.dpkt_list[idx]
            dialog = DetailDialog(tmp)
            dialog.exec()

    def show_sessions(self):
        try:
            dialog = ListDialog(self.sniffer.dpkts)
            dialog.exec()
        except:
            pass

    def KWsearch(self):
        # print('IPrefractor')
        # try:
        #     try:
        #         os.remove('tmp/reserved.pcap')
        #     except:
        #         pass
        #     wrpcap('tmp/reserved.pcap', self.sniffer.dpkts)
        #     self.dpkts = sniff(offline='tmp/reserved.pcap', session=IPSession,
        #                        filter=None if self.filter.text() == '' else self.filter.text())
        #     output = str(self.sniffer.dpkts) + '\nExtract sessions from packets: ' + str(
        #         len(self.sniffer.dpkts.sessions().keys())) + '.'
        #     for dpkt in self.sniffer.dpkts:
        #         summary = dpkt.summary()
        #         self.summaries.append(summary)
        #     self.slm.setStringList(self.summaries)  # 将数据设置到model
        #     self.output.setText(output)
        #     try:
        #         os.remove('tmp/test.jpg')
        #     except:
        #         pass
        #     self.sniffer.draw()
        #     self.feedback.setText("Sniff done.")
        #     pix = QPixmap('./tmp/test.jpg')
        #     self.QGP_item = QtWidgets.QGraphicsPixmapItem(pix)  # 创建像素图元
        #     self.scene.clear()
        #     self.scene.addItem(self.QGP_item)
        #
        #     self.signal.emit()
        # except:
        #     pass
        try:
            dialog = KWFListDialog(self.sniffer.dpkts)
            dialog.exec()
        except:
            pass

    def tcp_refractor(self):
        print('TCPrefractor')
        try:
            try:
                os.remove('tmp/reserved.pcap')
            except:
                pass
            wrpcap('tmp/reserved.pcap', self.sniffer.dpkts)
            self.dpkts = sniff(offline='tmp/reserved.pcap', session=TCPSession,
                               filter=None if self.filter.text() == '' else self.filter.text())
            output = str(self.sniffer.dpkts) + '\nExtract sessions from packets: ' + str(
                len(self.sniffer.dpkts.sessions().keys())) + '.'
            for dpkt in self.sniffer.dpkts:
                summary = dpkt.summary()
                self.summaries.append(summary)
            self.slm.setStringList(self.summaries)  # 将数据设置到model
            self.output.setText(output)
            try:
                os.remove('tmp/test.jpg')
            except:
                pass
            self.sniffer.draw()
            self.feedback.setText("Sniff done.")
            pix = QPixmap('./tmp/test.jpg')
            self.QGP_item = QtWidgets.QGraphicsPixmapItem(pix)  # 创建像素图元
            self.scene.clear()
            self.scene.addItem(self.QGP_item)

            self.signal.emit()
        except:
            print('TCP failed')

    def stop_backrun(self):
        try:
            stop_thread(self.thread)
        except:
            pass

    def closeEvent(self, event):
        try:
            stop_thread(self.thread)
        except:
            pass
        self.close()


class DetailDialog(QtWidgets.QDialog, Ui_Detail):
    def __init__(self, dpk):
        super(DetailDialog, self).__init__()
        self.setupUi(self)
        self.summary.setText(dpk.summary())
        self.tree.setText(dpk.show(dump=True))
        hex1, hex2 = hexstr(dpk).split('  ')[0:2]
        hex1_list = list(hex1)
        idx = 0
        cnt = 0
        for i in range(int(len(hex1) / 48) + 1):
            if cnt == 0:
                str_tmp = list('\n0000' + '    ')
            elif 0 < cnt < 100:
                str_tmp = list('\n00' + str(cnt) + '    ')
            elif 100 <= cnt < 1000:
                str_tmp = list('\n0' + str(cnt) + '    ')
            else:
                str_tmp = list('\n' + str(cnt) + '    ')
            for j in str_tmp:
                hex1_list.insert(idx, j)
                idx += 1
            idx += 48
            cnt += 10
        hex1 = ''.join(hex1_list)
        self.hex_orig.setText(hex1)
        hex2_list = list("" + hex2)
        idx = 0
        for i in range(int(len(hex2) / 16) + 1):
            hex2_list.insert(idx, '\n')
            idx += 17
        hex2 = ' '.join(hex2_list)
        self.hex_proc.setText(hex2)
        dpk.show()


# lst.replace( IP.ttl, 64 )
class SubWindow_analyze(QtWidgets.QMainWindow, Ui_Analyze):
    def __init__(self):
        super(SubWindow_analyze, self).__init__()
        self.setupUi(self)

        self.sniffer = Sniffer()
        self.worklog = ''
        self.summaries = []

        self.slm = QtCore.QStringListModel()  # 创建mode
        self.slm.setStringList(self.summaries)  # 将数据设置到model
        self.pkt_list.setModel(self.slm)  # 绑定 listView 和 model

        self.map_idx = []
        self.hex1 = ''
        self.hex2 = ''
        self.hex1_orig = ''
        self.hex2_orig = ''

        self.nameDict = {'IP.src': IP.src, 'IP.ttl': IP.ttl, 'TCP.sport': TCP.sport, 'TCP.dport': TCP.dport}

    def go_on_clicked(self):
        pass

    def item_on_clicked(self):
        idx = self.pkt_list.currentIndex().row()  # 这个值就是所选的列表值
        tmp = self.sniffer.dpkts[idx]
        self.add_log('Choose {}'.format(tmp.summary()))
        self.summary.setText(tmp.show(dump=True))
        self.edit_in(tmp)

    def hex_changed(self):
        try:
            if self.hex1_orig is not None and self.hex2_orig is not None:
                hex1_new = self.HexTextEdit.toPlainText()
                diff = find_diff(self.hex1_orig, hex1_new)
                print(diff)
                for i in diff:
                    row = i // 57
                    col = i % 57 - 9
                    if 0 <= col <= 47:
                        # print("self.hex1[0]\n" + self.hex1[0])
                        # print("self.hex1\n" + self.hex1)
                        # print("hex1_new\n" + hex1_new)
                        self.add_log('The {} th is changed from {} to {}.'.format(row * 32 + col - col // 3,
                                                                                  self.hex1[row * 32 + col - col // 3],
                                                                                  hex1_new[i]))
                        self.hex1 = list(self.hex1)
                        self.hex1[row * 32 + col - col // 3 - 1] = hex1_new[i]
                        self.hex1 = ''.join(self.hex1)
                        # pkt_new = import_hexcap(self.hex1+'  '+self.hex2)
                        # print('pkt_new:', pkt_new)
                        # pkt_new.show()
                        # idx = self.pkt_list.currentIndex().row()  # 这个值就是所选的列表值
                        # print(hexdump(self.sniffer.dpkts[idx]))
                        # print(hexdump(pkt_new))
                        # self.sniffer.dpkts[idx] = pkt_new
        except:
            print(len(self.hex1_orig), len(self.HexTextEdit.toPlainText()))
            return None

    def ascii_changed(self):
        print('ascii_changed')
        # chr(int("0x53", 16))

    def save_on_clicked(self):
        self.sniffer.save()

    def recover_on_clicked(self):
        pass

    def send_on_clicked(self):
        pass

    def quick_modify_on_clicked(self):
        tmp = list(self.nameDict.keys())
        res, flag = QMDialog.getResult(l=tmp)
        print('res=', res)
        print(str(self.sniffer.dpkts))
        if flag:
            for r in res:
                if len(r) == 2:
                    # self.sniffer.dpkts.replace(self.nameDict[r[0]], r[1])
                    if r[0] == 1:
                        self.sniffer.dpkts = self.sniffer.dpkts.replace(self.nameDict[list(self.nameDict)[r[0]]],
                                                                        int(r[1]))
                    else:
                        self.sniffer.dpkts = self.sniffer.dpkts.replace(self.nameDict[list(self.nameDict)[r[0]]], r[1])
                elif len(r) == 3:
                    self.sniffer.dpkts = self.sniffer.dpkts.replace(self.nameDict[list(self.nameDict)[r[0]]], int(r[1]),
                                                                    int(r[2]))
            self.add_log('New dpkts Reload Done!')
            self.summaries = []
            for dpkt in self.sniffer.dpkts:
                summary = dpkt.summary()
                self.summaries.append(summary)
            self.slm.setStringList(self.summaries)  # 将数据设置到model

    def open_triggered(self):
        fname = QtWidgets.QFileDialog.getOpenFileName(self, 'open file', r'./pcap/')
        self.clear()
        f = self.filter_input.text()
        if fname[0]:
            try:
                print(fname)
                self.sniffer.load(fname[0], filter=f)
                self.add_log('Load {} Done!'.format(fname[0]))
                for dpkt in self.sniffer.dpkts:
                    summary = dpkt.summary()
                    self.summaries.append(summary)
                self.slm.setStringList(self.summaries)  # 将数据设置到model
            except:
                self.workbench.setText("打开文件失败，可能是文件发生错误")

    def save_triggered(self):
        self.sniffer.save()

    def add_log(self, str):
        self.worklog = self.worklog + str + '\n\n'
        self.workbench.setText(self.worklog)
        row = self.workbench.height() - self.scrollArea_2.verticalScrollBar().height() + 200
        self.scrollArea_2.verticalScrollBar().setValue(row)

    def clear(self):
        self.summaries = []
        self.slm.setStringList(self.summaries)  # 将数据设置到model
        self.summary.setText('')
        self.HexTextEdit.clear()
        self.AsciiTextEdit.clear()

    def edit_in(self, dpk):
        hex1, hex2 = hexstr(dpk).split('  ')[0:2]
        hex1_list = list(hex1)
        self.hex1 = hex1
        self.hex2 = hex2
        idx = 0
        cnt = 0
        for i in range(int(len(hex1) / 48) + 1):
            if cnt == 0:
                str_tmp = list('\n0000' + '    ')
            elif 0 < cnt < 100:
                str_tmp = list('\n00' + str(cnt) + '    ')
            elif 100 <= cnt < 1000:
                str_tmp = list('\n0' + str(cnt) + '    ')
            else:
                str_tmp = list('\n' + str(cnt) + '    ')
            for j in str_tmp:
                hex1_list.insert(idx, j)
                idx += 1
            idx += 48
            cnt += 10
        hex1 = ''.join(hex1_list)
        self.hex1_orig = hex1
        self.HexTextEdit.setPlainText(hex1)
        hex2_list = list("" + hex2)
        idx = 0
        for i in range(int(len(hex2) / 16) + 1):
            hex2_list.insert(idx, '\n')
            idx += 17
        hex2 = ' '.join(hex2_list)
        self.hex2_orig = hex2
        self.AsciiTextEdit.setPlainText(hex2)


class TextDialog(QtWidgets.QDialog, Ui_TextDialog):
    def __init__(self, str):
        super(TextDialog, self).__init__()
        self.setupUi(self)
        self.pushButton.setVisible(False)
        self.pushButton_2.setVisible(False)
        self.pushButton_3.setVisible(False)
        self.pushButton_4.setVisible(False)
        self.lineEdit.setVisible(False)
        self.label.setText(str)

    def func1(self):
        pass

    def func2(self):
        pass

    def func3(self):
        pass

    def func4(self):
        pass

    def return_pressed(self):
        pass


class ListDialog(QtWidgets.QDialog, Ui_ListDialog):
    def __init__(self, dpkts):
        super(ListDialog, self).__init__()
        self.setupUi(self)
        self.listView.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.pushButton.setVisible(False)
        self.pushButton_2.setVisible(False)
        self.pushButton_3.setVisible(False)
        self.pushButton_4.setVisible(False)
        self.lineEdit.setVisible(False)
        self.label.setText('----已根据Session对抓到的包进行分组----')
        self.sessions = dpkts.sessions()
        self.l = []
        for key in self.sessions.keys():
            self.l.append(':    '.join([key, str(self.sessions[key])]))
        self.slm = QtCore.QStringListModel()  # 创建mode
        self.slm.setStringList(self.l)  # 将数据设置到model
        self.listView.setModel(self.slm)  # 绑定 listView 和 model
        self.pushButton.setText('保存')

    def func1(self):
        # idx = self.listView.currentIndex()
        # self.sniffer = Sniffer()
        # self.sniffer.dpkts = self.sessions[idx]
        # self.sniffer.save()
        pass

    def func2(self):
        pass

    def func3(self):
        pass

    def func4(self):
        pass

    def return_pressed(self):
        pass

    def item_double_clicked(self):
        idx = self.listView.currentIndex().row()  # 这个值就是所选的列表值
        dpkts = self.sessions[list(self.sessions.keys())[idx]]
        dialog = ListDialogDetail(dpkts)
        dialog.exec()


class KWFListDialog(QtWidgets.QDialog, Ui_ListDialog):
    def __init__(self, dpkts):
        super(KWFListDialog, self).__init__()
        self.setupUi(self)
        self.listView.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.pushButton.setVisible(True)
        self.pushButton_2.setVisible(False)
        self.pushButton_3.setVisible(False)
        self.pushButton_4.setVisible(False)
        self.lineEdit.setVisible(True)
        self.label.setText('----您可以在此输入关键字进行包过滤----')
        self.dpkts = dpkts
        self.l = []
        for pkt in self.dpkts:
            self.l.append(pkt.summary())
        self.slm = QtCore.QStringListModel()  # 创建mode
        self.slm.setStringList(self.l)  # 将数据设置到model
        self.listView.setModel(self.slm)  # 绑定 listView 和 model
        self.tmp_map = None

    def func1(self):
        keyword = self.lineEdit.text()
        tmp = []
        self.tmp_map = []
        cnt = 0
        for pkt in self.dpkts:
            if keyword.strip() in pkt.show(dump=True):
                tmp.append(pkt)
                self.tmp_map.append(cnt)
            cnt += 1
        self.l = []
        for pkt in tmp:
            self.l.append(pkt.summary())
        self.slm.setStringList(self.l)  # 将数据设置到model
        self.label.setText('-----已根据关键字{}过滤数据包------'.format(keyword))

    def func2(self):
        pass

    def func3(self):
        pass

    def func4(self):
        pass

    def return_pressed(self):
        pass

    def item_double_clicked(self):
        idx = self.listView.currentIndex().row()  # 这个值就是所选的列表值
        if self.tmp_map is not None:
            pkt = self.dpkts[self.tmp_map[idx]]
            dialog = TextDialog(pkt.show(dump=True))
            dialog.exec()
        else:
            dialog = TextDialog(self.dpkts[idx].show(dump=True))
            dialog.exec()


class ListDialogDetail(QtWidgets.QDialog, Ui_ListDialog):
    def __init__(self, dpkts):
        super(ListDialogDetail, self).__init__()
        self.setupUi(self)
        self.listView.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.pushButton.setVisible(False)
        self.pushButton_2.setVisible(False)
        self.pushButton_3.setVisible(False)
        self.pushButton_4.setVisible(False)
        self.lineEdit.setVisible(False)
        self.label.setText("----与该seesion相关联的数据包----")

        self.dpkts = dpkts
        self.slm = QtCore.QStringListModel()  # 创建mode
        self.listView.setModel(self.slm)  # 绑定 listView 和 model
        self.summaries = []
        for dpkt in dpkts:
            summary = dpkt.summary()
            self.summaries.append(summary)
        self.slm.setStringList(self.summaries)  # 将数据设置到model

    def func1(self):
        pass

    def func2(self):
        pass

    def func3(self):
        pass

    def func4(self):
        pass

    def return_pressed(self):
        pass

    def item_double_clicked(self):
        idx = self.listView.currentIndex().row()  # 这个值就是所选的列表值
        tmp = self.dpkts[idx]
        dialog = DetailDialog(tmp)
        dialog.exec()


# TODO
class QMDialog(QtWidgets.QDialog, Ui_QMDialog):
    def __init__(self, l: list = None):
        super(QMDialog, self).__init__()
        if l is None:
            l = []
        print(l)
        self.setupUi(self)
        self.modify = []
        for item in l:
            self.comboBox.addItem(str(item))

    def add_on_clicked(self):
        idx = self.comboBox.currentIndex()
        text = self.input.text()
        texts = text.split(',')
        text = [idx]
        for tex in texts:
            text.append(tex.strip())
        self.modify.append(tuple(text))
        print(type(text))
        if len(text) == 2:
            self.workbench.setText(self.workbench.text() + '\nChange ' + self.comboBox.itemText(idx) + ' to ' + text[1])
        else:
            self.workbench.setText(
                self.workbench.text() + '\nChange ' + self.comboBox.itemText(idx) + ' from ' + text[1] + ' to ' + text[
                    2])

    @staticmethod
    def getResult(l):
        dialog = QMDialog(l)
        result = dialog.exec()
        return dialog.modify, result == QtWidgets.QDialog.Accepted


class Monitor(QtWidgets.QDialog, Ui_Monitor):
    update_signal = QtCore.pyqtSignal(str)
    max_num = 60
    graph_signal = QtCore.pyqtSignal()

    def __init__(self, string=''):
        super(Monitor, self).__init__()
        self.setupUi(self)
        self.name = string
        self.update_signal.connect(self.counter)
        self.update_signal.connect(self.myupdate)
        self.interval = int(time.time())
        self.series_ = [0] * self.max_num
        self.start = self.interval - self.max_num
        self.graphicsView.chart().setTitle('网络流量')

        self.graphicsView.setRenderHint(QPainter.Antialiasing)
        import psutil
        info = psutil.net_if_addrs()
        for k, _ in info.items():
            self.comboBox.addItem(k)
        self.t = time.time()
        self.thread = threading.Thread(target=self.backRun)
        self.thread.setDaemon(True)
        self.thread.start()

    def myupdate(self):
        if time.time() - self.t > 0.5:
            self.graphicsView.chart().removeAllSeries()
            self.graphicsView.chart().setTitle("网络流量速率")
            series = QLineSeries(self.graphicsView.chart())
            series.setName('{}'.format(self.name))
            max = 0
            min = 100000
            for t_, cnt_ in zip((i for i in range(self.start, self.start + self.max_num)), self.series_):
                if cnt_ > max:
                    max = cnt_
                if cnt_ < min:
                    min = cnt_
                series.append(t_, cnt_)
            self.graphicsView.chart().addSeries(series)
            self.graphicsView.chart().createDefaultAxes()
            self.t = time.time()

    def counter(self, string):
        t = time.time()
        if self.interval <= t < self.interval + 1:
            self.series_[-1] += 1
        else:
            n = int(t - self.interval)
            while n:
                self.series_.pop(0)
                self.start += 1
                self.series_.append(0)
                if self.interval <= t < self.interval + 1:
                    self.series_[-1] += 1
                n -= 1
                self.interval += 1
            self.interval = int(t)
        # print(self.series_)

    def backRun(self):
        try:
            iface = self.comboBox.currentText()
            filter = self.lineEdit.text()
            self.sniffer = Sniffer(iface=iface, filter=filter, prn=self.update_signal)
            self.sniffer.run()
        except:
            pass

    def iface_changed(self):
        pass

    def filter_changed(self):
        pass

    def start_on_clicked(self):
        stop_thread(self.thread)
        self.clear()
        self.thread = threading.Thread(target=self.backRun)
        self.thread.setDaemon(True)
        self.thread.start()

    def clear_on_clicked(self):
        pass

    def clear(self):
        self.interval = int(time.time())
        self.series_ = [0] * self.max_num
        self.start = self.interval - self.max_num

    def closeEvent(self, event):
        try:
            stop_thread(self.thread)
        except:
            pass
        self.close()


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    win = MainWindow()
    sub1 = SubWindow_capture()
    sub2 = SubWindow_analyze()
    win.show()
    sys.exit(app.exec_())
