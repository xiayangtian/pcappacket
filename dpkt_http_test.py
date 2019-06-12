# -*- coding: utf8 -*-
import dpkt
import datetime
import socket
import pcap
from dpkt.compat import compat_ord


def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)

def inet_to_str(inet):
    return socket.inet_ntoa(inet)

def analyse_from_packet():
    with open(r'D:\Project\http.pcap','rb') as f:
        pcapdata = dpkt.pcap.Reader(f)
        print_http_requests(pcapdata)

def analyse_from_stream(eth_name='eth4'):
    pc = pcap.pcap(eth_name)
    print_http_requests(pc)

def print_http_requests(pcapdata):
    count = 0
    for timestamp,buf in pcapdata:
        count += 1
        if count==100:
            pass
            #break
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            print ("Non IP Packet type, not supported %s\n" % eth.data.__class__.__name__)
            continue
        ip = eth.data
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            try:
                request = dpkt.http.Request(tcp.data)
            except(dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue
            do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
            more_fragments = bool(ip.off & dpkt.ip.IP_MF)
            fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
            print(count)
            print('Timestamp: '+ str(datetime.datetime.utcfromtimestamp(timestamp)))
            print 'Ethernet Frame: '+ mac_addr(eth.src), mac_addr(eth.dst), eth.type
            print('IP: %s -> %s \n\tlen=%d ttl=%d DF=%d MF=%d offset=%d' %
                  (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))
            print('HTTP request: %s\n' % repr(request))
if __name__ == '__main__':

    analyse_from_packet()
    #analyse_from_stream()
