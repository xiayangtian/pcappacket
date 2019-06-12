# -*- coding:utf-8 -*-
import pcap
import dpkt

def readsmtp():
    fp = open(r'D:\Project\smtp.pcap','rb')
    data = dpkt.pcap.Reader(fp)
    analyse(data)
    fp.close()

def analyse(pcapdata):
    count = 0
    for timestamp,data in pcapdata:
        if(count == 72):
            break
        dpktdata = dpkt.ethernet.Ethernet(data)
        tcpdata = dpktdata.data.data
        if isinstance(tcpdata,dpkt.tcp.TCP):
            if ((tcpdata.sport == 25) or (tcpdata.dport == 25)):
                print tcpdata.data

        count += 1
if __name__ == "__main__":
    readsmtp()