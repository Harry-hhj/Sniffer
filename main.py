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
    def __init__(self, iface="en0", session="", filter="ip", count=0, timeout=None, prn=None):
        self.dpkts = None
        self.dpkt_list = []
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
        self._last_time = time.time()
        self.prn = prn
        # self.packet = None

    def packet_callback(self, packet):
        # print("Flow rate: ", packet['IP'].len / 1024 / 1024 / (time.time() - self._last_time))
        # if time.time() - self._last_time > 0:
        #     self._last_time = time.time()
        #     summary = packet.summary()
        #     self.dpkt_list.append(packet)
        #     self.dpkts = PacketList(self.dpkt_list)
        #     if self.prn is not None:
        #         self.prn.emit(summary)
        summary = packet.summary()
        self.dpkt_list.append(packet)
        if self.prn is not None:
            # self.packet = packet
            self.prn.emit(summary)
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

    def save(self, name=None):
        if name is None:
            wrpcap("./pcap/{}.pcap".format(TimeStamp2Time(time.time())), self.dpkts)
        else:
            wrpcap("./pcap/{}.pcap".format(str(name)), self.dpkts)

    def load(self, file="./pcap/2020-12-16 13:54:18.pcap", filter=''):
        self.dpkts = sniff(offline=file, filter=filter)

    def search(self, string):
        for pkt in self.dpkts:
            if string in pkt.show(dump=True):
                print('='*30)
                pkt.draw()

    def modify(self, idx):
        self.dpkts[idx].replace( IP.src, "192.168.1.1", "10.0.0.1" )

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
    # print(str(s.dpkts))
    # print(s.dpkts.sessions())
    # s.search('HTTP/1.1')

    # s = Sniffer()
    # s.load()
    # print('--'*10)
    # print('--'*10)
    # print('--'*10)
    # s.dpkts = s.dpkts.replace(IP.ttl, 64)
    # s.dpkts.show()
    # print('--'*20)
    # for dpk in s.dpkts:
    #     if dpk['IP'].ttl != 64:
    #         print(dpk['IP'].ttl)
    # print(s.dpkts.sr()[0].show())
    # print(s.dpkts.sr()[1].show())

    # dpkts = sniff(timeout=5)
    # print(dpkts)
    # try:
    #     import os
    #     os.remove('tmp/reserved.pcap')
    # except:
    #     pass
    # wrpcap('tmp/reserved.pcap', dpkts)
    # dpkts = sniff(offline='tmp/reserved.pcap', session=TCPSession, filter='')
    # print(dpkts)

    IFACES.show(True)
