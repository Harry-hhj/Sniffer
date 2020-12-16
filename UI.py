from PyQt5 import QtWidgets, QtCore
from PyQt5.QtGui import QImage, QPixmap
from entry import Ui_Entry
from capture import Ui_Capture
from detail import Ui_Detail
from analyze import Ui_Analyze
from main import Sniffer

from scapy.all import *
import numpy


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


class MainWindow(QtWidgets.QMainWindow, Ui_Entry):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.setupUi(self)

    def capture_on_clicked(self):
        sub1.show()

    def analyze_on_clicked(self):
        sub2.show()

    def monitor_on_clicked(self):
        print("monitor_on_clicked")

    def exit_on_clicked(self):
        sys.exit()

    def closeEvent(self, event):
        sys.exit(0)


class SubWindow_capture(QtWidgets.QMainWindow, Ui_Capture):
    def __init__(self):
        super(SubWindow_capture, self).__init__()
        self.setupUi(self)
        self.summaries = []

        self.slm = QtCore.QStringListModel()  # 创建mode
        self.slm.setStringList(self.summaries)  # 将数据设置到model
        self.pkt_list.setModel(self.slm)  # 绑定 listView 和 model

        self.zoomscale = 1.0

    def start_on_clicked(self):
        iface = self.iface.text()
        if iface == '':
            iface = 'en0'
        filter = self.filter.text()
        session = self.session.text()
        count = 0 if self.count.text() == '' else eval(self.count.text())
        if self.timeout.text() == '':
            timeout = None
        else:
            timeout = eval(self.timeout.text())
        if count == 0 and timeout is None:
            timeout = 10
        password = self.password.text()
        self.summaries = []
        self.slm.setStringList(self.summaries)  # 将数据设置到model
        self.feedback.setText("Begin to sniff........Please wait.")
        self.feedback.update()
        self.sniffer = Sniffer(iface=iface, filter=filter, session=session, count=count, timeout=timeout)
        self.sniffer.run()
        print("finish")
        output = str(self.sniffer.dpkts)
        for dpkt in self.sniffer.dpkts:
            summary = dpkt.summary()
            self.summaries.append(summary)
        self.output.setText(output)
        self.slm.setStringList(self.summaries)  # 将数据设置到model

        self.sniffer.draw()
        self.feedback.setText("Sniff done.")
        # opencv图像
        # pix = QPixmap.fromImage(frame)
        # self.item = QGraphicsPixmapItem(pix)  # 创建像素图元
        # # self.item.setScale(self.zoomscale)
        # self.scene = QGraphicsScene()  # 创建场景
        # self.scene.addItem(self.item)
        # self.picshow.setScene(self.scene)  # 将场景添加至视图
        pix = QPixmap('./tmp/test.jpg')
        self.QGP_item = QtWidgets.QGraphicsPixmapItem(pix)  # 创建像素图元
        # self.item.setScale(self.zoomscale)
        self.scene = QtWidgets.QGraphicsScene()  # 创建场景
        self.scene.addItem(self.QGP_item)
        self.graphicsView.setScene(self.scene)  # 将场景添加至视图

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

    def text_changed(self):
        # 没有语法检查器，所以不实现自动检测输入变化
        pass

    def pkts_double_clicked(self):
        idx = self.pkt_list.currentIndex().row()  # 这个值就是所选的列表值
        tmp = self.sniffer.dpkts[idx]
        dialog = Dialog(tmp)
        dialog.exec()


class Dialog(QtWidgets.QDialog, Ui_Detail):
    def __init__(self, dpk):
        super(Dialog, self).__init__()
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

        self.loadMode = False
        self.map_idx = []

    def go_on_clicked(self):
        pass

    def item_on_clicked(self):
        idx = self.pkt_list.currentIndex().row()  # 这个值就是所选的列表值
        tmp = self.sniffer.dpkts[idx]
        self.add_log('Choose {}'.format(tmp.summary()))
        self.summary.setText(tmp.show(dump=True))
        self.edit_in(tmp)

    def hex_changed(self):
        print('hex_changed')
        if not self.loadMode:
            pass

    def ascii_changed(self):
        print('ascii_changed')

    def save_on_clicked(self):
        pass

    def recover_on_clicked(self):
        pass

    def send_on_clicked(self):
        pass

    def more_on_clicked(self):
        pass

    def open_triggered(self):
        self.loadMode = True
        fname = QtWidgets.QFileDialog.getOpenFileName(self, 'open file', r'~/PycharmProjects/sniffer/pcap/')
        self.clear()
        if fname[0]:
            try:
                print(fname)
                self.sniffer.load(fname[0])
                self.add_log('Load {} Done!'.format(fname[0]))
                for dpkt in self.sniffer.dpkts:
                    summary = dpkt.summary()
                    self.summaries.append(summary)
                self.slm.setStringList(self.summaries)  # 将数据设置到model
            except:
                self.workbench.setText("打开文件失败，可能是文件发生错误")
        self.loadMode = False

    def save_triggered(self):
        pass

    def add_log(self, str):
        self.worklog = self.worklog + str + '\n\n'
        self.workbench.setText(self.worklog)
        row = self.workbench.height()-self.scrollArea_2.verticalScrollBar().height()+200
        self.scrollArea_2.verticalScrollBar().setValue(row)

    def clear(self):
        self.summaries = []
        self.slm.setStringList(self.summaries)  # 将数据设置到model
        self.summary.setText('')

    def edit_in(self, dpk):
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
        self.HexTextEdit.setPlainText(hex1)
        hex2_list = list("" + hex2)
        idx = 0
        for i in range(int(len(hex2) / 16) + 1):
            hex2_list.insert(idx, '\n')
            idx += 17
        hex2 = ' '.join(hex2_list)
        self.AsciiTextEdit.setPlainText(hex2)



if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    win = MainWindow()
    sub1 = SubWindow_capture()
    sub2 = SubWindow_analyze()
    win.show()
    sys.exit(app.exec_())
