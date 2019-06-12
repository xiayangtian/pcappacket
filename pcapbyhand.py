# -*- coding:utf-8 -*-
import sys
import socket
import struct
import os
import time
def long2ip(long):
    floor_list=[]
    yushu=long
    for i in reversed(range(4)):   #3,2,1,0
        res=divmod(yushu,256**i)
        floor_list.append(str(res[0]))
        yushu=res[1]
    return '.'.join(floor_list)

time1=time.time()
fp = open(r'C:\Users\hasee\Desktop\tcppcap.pcap', "rb")
fpwrite = open(r'result.txt','w')
data = fp.read(24)
(Magic,Major,Minor,ThisZone,SigFigs,SnapLen,LinkType) = struct.unpack('<IHHIIII',data)
count = 0
while(True):
    count += 1
    data = fp.read(16)
    if(data==''):
        break
    (TimeH,TimeL,Caplen,Len) = struct.unpack('<IIII',data)

    data = fp.read(14)
    data = fp.read(1)
    (IPVersion) = struct.unpack('<B',data)
    #print(IPVersion[0])
    if(IPVersion[0]!=0x45):
        fp.read(Len-15)
    else:
        data = fp.read(19)
        (temp,TotalLen,ID,Flag_Segment,TTL,Protocol,Checksum,SrcIP,DstIP) = struct.unpack('>BHHHBBHII',data)
        if(Protocol!=6):
            fp.read(Len-34)
        else:
            data = fp.read(20)
            (SrcPort,DstPort,SeqNo,AckNo,HeaderLen,Flags,Window,ChecksumTCP,UrgentP) = struct.unpack('>HHIIBBHHH',data)
            if(Len>54):
                fp.read(Len-54)
            fpwrite.write('序号:%d\nIP协议版本:4\nIP源地址:%s\nIP目的地址:%s\n源端口:%d\n目的端口:%d\n\n'%(count,long2ip(SrcIP),long2ip(DstIP),SrcPort,DstPort))

fp.close()
fpwrite.close()
time2=time.time()
print(time2-time1)

