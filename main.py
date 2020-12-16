from scapy.all import *
import time

protrol_filter = ''


def arp_monitor_callback(pkt):
    if 'ARP' in pkt and pkt['ARP'].op in (1, 2):  # who-has or is-at
        return pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")


# 时间戳转换函数
def TimeStamp2Time(timeStamp):
    timeTmp = time.localtime(timeStamp)  # time.localtime()格式化时间戳为本地时间
    myTime = time.strftime("%Y-%m-%d %H:%M:%S", timeTmp)  # 将本地时间格式化为字符串
    return myTime


class Sniffer(object):
    def __init__(self, iface="en0", session="", filter="ip", count=0, timeout=None):
        self.dpkts = None
        self.auto_show = True
        self.sniffer = None
        if iface == '':
            self.iface = iface
        else:
            self.iface="en0"
        self.filter = filter
        if session == 'IPSession':
            self.session = IPSession
        elif session == 'TCPSession':
            self.session = TCPSession
        else:
            self.session = None
        self.count = count
        self.timeout = timeout
        self._last_time = None

    def packet_callback(self, packet):
        pass
        # print("Flow rate: ", packet['IP'].len / 1024 / 1024 / (time.time() - self._last_time))
        summary = packet.summary()
        # print(summary)
        # packet.draw()
        # print(type(hexdump(packet)))
        # print(hexstr(packet).split('  '))
        # self._last_time = time.time()


        # if packet['Ether'].payload:
        #     print(packet['Ether'].src)
        #     print(packet['Ether'].dst)
        #     print(packet['Ether'].type)
        #     print(hexstr(packet['Ether'].payload))

        # if packet['ARP'].payload:
        #     print(packet['ARP'].psrc)
        #     print(packet['ARP'].pdst)
        #     print(packet['ARP'].hwsrc)
        #     print(packet['ARP'].hwdst)

    def run(self, auto_show=False):
        self.auto_show = auto_show
        self._last_time = time.time()
        self.dpkts = sniff(iface=self.iface, session=self.session, filter=self.filter, count=self.count,
                           timeout=self.timeout, prn=self.packet_callback)

    def set(self, param, value):
        pass

    def save(self):
        wrpcap("{}.pcap".format(TimeStamp2Time(time.time())), self.dpkts)

    def load(self, file="./pcap/2020-12-16 13:54:18.cap"):
        self.dpkts = sniff(offline=file, filter='tcp')

    def search(self, string):
        for pkt in self.dpkts:
            if string in pkt:
                print('='*30)
                pkt.draw()

    def draw(self):
        self.dpkts.conversations(type='jpg', target="> tmp/test.jpg")


if __name__ == '__main__':
    # dpkts = sniff(iface="en0", session=IPSession, filter='', count=100)
    # dpkts.conversations(type='jpg', target="> test.jpg")
    # ls('ARP')
    # for dpkt in dpkts:
    #     print(dpkt.show(dump=True))
    #
    # print('-' * 10)
    # flags = []
    # for dpkt in dpkts:
    #     if 'IP' in dpkt:
    #         print(dpkt.summary())
    #         print(int(dpkt['IP'].flags))
    #         print(dpkt['IP'].flags)
    #         if dpkt['IP'].flags not in flags:
    #             flags.append(dpkt['IP'].flags)
    # print(flags)

    # s = Sniffer(iface="en0", session='', filter='tcp', timeout=10)
    # s.run()
    # s.draw()
    # print(str(s.dpkts))
    # s.search('HTTP/1.1')

    # s = Sniffer()
    # s.load()
    # input('asd')
    # s.draw()

    import numpy as np

    def find_diff(a, b):
        diff_index = np.array(list(a)) != np.array(list(b))
        print(diff_index)
        print(np.where(diff_index==True)[0].tolist())


    find_diff("aafsjdls;afjkdls;kf", "aafsjdes;afjkdws;kf")
