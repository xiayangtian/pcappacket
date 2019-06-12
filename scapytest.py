# -*- coding:utf-8 -*-
import time
from scapy.all import *
from scapy.utils import PcapReader,PcapWriter
if __name__ == '__main__':
    time1 = time.time()
    s1 = PcapReader(r'C:\Users\hasee\Desktop\tcppcap.pcap')
    fpwrite = open(r'resultbyscapy.txt', 'w')
    count = 0
    while (True):
        count += 1
        data = s1.read_packet()
        if(data==None):
            break
        if (data['Ethernet'].type==0x0800):
            if(data['IP'].proto==6):
                fpwrite.write('序号:%d\nIP协议版本:4\nIP源地址:%s\nIP目的地址:%s\n源端口:%d\n目的端口:%d\n\n' % (count, data['IP'].src, data['IP'].dst, data['TCP'].sport, data['TCP'].dport))
    fpwrite.close()
    s1.close()

    time2 = time.time()
    print(time2 - time1)