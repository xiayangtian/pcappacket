# -*- coding: utf8 -*-
import dpkt
import datetime
import socket
import pcap
from dpkt.compat import compat_ord
def copy_from_packet():
    oldtest = open(r'D:\Project\ip.pcap', 'rb')
    f = dpkt.pcap.Reader(oldtest)
    copy_active(f)
    oldtest.close()

def copy_from_stream(eth_name='eth4'):
    pc = pcap.pcap(eth_name)
    copy_active(pc)

def copy_active(pcapdata):
    newtest = open(r'D:\Project\newtest.pcap', 'wb')
    writer = dpkt.pcap.Writer(newtest)
    count = 0
    for timestamp,buf in pcapdata:
        count += 1
        if count == 10:
            break
        eth = dpkt.ethernet.Ethernet(buf)
        #限制条件
        #eth.data.src = socket.inet_aton("192.168.1.164")
        #eth.data.dst = socket.inet_aton("192.168.1.196")
        writer.writepkt(eth)
        newtest.flush()
    newtest.close()

if __name__ == "__main__":
    #copy_from_packet()
    copy_from_stream()