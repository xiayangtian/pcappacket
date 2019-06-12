# -*- coding: utf8 -*-
import pcap
import dpkt
import time
def capt_data(eth_name="eth4", p_type=None):
    """
    捕获网卡数据包
    :param eth_name  网卡名，eg. eth1,eth4，最高到eth9(wlan网卡名)
    :param p_type    日志捕获类型 1：sdk日志用例分析 2：目标域名过滤输出 3：原始数据包
    :return:
    """

    pc = pcap.pcap(eth_name)
    #pc.setfilter('tcp port 80')  # 设置监听过滤器
    print 'start capture....'
    count = 0
    if pc:
        for p_time, p_data in pc:# p_time为收到时间，p_data为收到数据
            analyze(p_data)
            if(count == 10):
                break
            count+=1
def analyze(pdata):
    p=dpkt.ethernet.Ethernet(pdata)
    if(p.data.__class__.__name__=='IP'):
        src_ip = '%d.%d.%d.%d' % tuple(map(ord, list(p.data.src)))
        dst_ip = '%d.%d.%d.%d' % tuple(map(ord, list(p.data.dst)))
        print src_ip
        print dst_ip
        if(p.data.data.__class__.__name__=='TCP'):
            tcp_data = p.data.data
            src_port = tcp_data.sport
            dst_port = tcp_data.dport
            print src_port
            print dst_port
            print "tcp_data:", tcp_data.data
        else:
            print("NOT TCP")
def anly_capt(p_time, p_data, p_type):
    """
    解析数据包
    :param p_data  收到数据
    :param p_type  日志捕获类型 1：sdk日志用例分析 2：目标域名过滤输出 3：原始数据包
    :return:
    """

    p = dpkt.ethernet.Ethernet(p_data)
    if p.data.__class__.__name__ == 'IP':
        ip_data = p.data
        src_ip = '%d.%d.%d.%d' % tuple(map(ord, list(ip_data.src)))
        dst_ip = '%d.%d.%d.%d' % tuple(map(ord, list(ip_data.dst)))
        if p.data.data.__class__.__name__ == 'TCP':
            tcp_data = p.data.data
            if tcp_data.dport == 80:
                # print tcp_data.data
                if tcp_data.data:
                    # 调用日志模块，对日志进行处理
                    if p_type == 1:
                        # sdk日志用例分析
                        tmp = tcp_data.data.strip()
                        global req_data, times
                        if tmp.startswith("POST") or tmp.startswith("GET"):  # or times > 0
                            if req_data:
                                pass
                            req_data = tmp + "\n"
                                # times = 0
                        else:
                            req_data = req_data + tmp
                                # times = times + 1

                    elif p_type == 2:
                        # 目标域名过滤输出
                        print "tcp_data:", tcp_data.data

                    else:
                        # 无过滤条件输出
                        print "tcp_data:", tcp_data.data
if __name__ == '__main__':
    time1 = time.time()
    capt_data()
    time2 = time.time()
    print(time2-time1)