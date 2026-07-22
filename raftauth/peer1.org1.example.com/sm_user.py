"""
相比LISP1，LISP2用socket模块实现数据报的封装和解封装，速率要快一些
"""

from scapy.all import *
import time
import socket
import psutil
import threading
from configure import *
import json


def sm_register(*params):
    if len(params) == 2:
        flag = params[0]
        SUPI = params[1]
        EID = myEID
    else:
        flag = params[0]
        SUPI = params[1]
        EID = params[2]
    # SUPI = str(uuid.uuid3(uuid.NAMESPACE_DNS, SUPI))
    if flag != 'ur' and flag != 'ud' and flag != 'rr':
        print("Error! Flag should be 'ur', 'ud' or 'rr'.")
        print('-' * 150)
        return
    gateway_socket = (gateway_EID, sm_register_port)
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.bind((myEID, random.choice(range(11111, 22222))))
    connection.connect(gateway_socket)
    connection.send((flag + '+++' + SUPI + '+++' + EID).encode('utf-8'))
    reply = connection.recv(1024).decode('utf-8')
    if reply == 'True':
        if flag == 'ur':
            print('user EID %s successfully register!' % EID)
        elif flag == 'ud':
            print('user EID %s successfully delete!' % EID)
        else:
            print('resource EID %s successfully register!' % EID)
        connection.close()
        print('-' * 150)
        return True
    else:
        print('Error! ', reply)
        connection.close()
        print('-' * 150)
        return


def send_data(my_port, her_EID, her_port, payload):
    my_port = str(my_port)
    her_port = str(her_port)
    data={
        'version': 4,
        'ihl':5,
        'tos': '0x0005',
        'len': len(payload) + 20,
        'id': random.choice(range(1, 65535)),
        'flags':0,
        'offset':0,
        'ttl': random.choice(range(1, 256)),
        'proto': random.choice(['icmp', 'ftp', 'smtp', 'dns', 'telnet', 'http', 'snmp', 'irc', 'ssh']),
        'options':None,
        'padding':None,
        'srcIP':myEID,
        'srcPort':int(my_port),
        'dstIP':her_EID,
        'dstPort':int(her_port),
        'payload':payload,
    }
    if data['len']>100:
        print('[%s:%s]--->[%s:%s] | %d bytes' % (myEID, my_port, her_EID, her_port, data['len']))
    else:
        print('[%s:%s]--->[%s:%s] | %s' % (myEID, my_port, her_EID, her_port, payload))
    data = json.dumps(data).encode('utf-8')
    s.sendto(data, (gateway_EID, sm_accessnet_port))
    print('-' * 150)


def recv_data():
    def process_recv_data(data):
        # print('-' * 50, 'Receive data', '-' * 50)
        data = json.loads(data[0].decode())
        # print('[%s:%d]--->[%s:%d] | %s' % (data[0], int(data[1]), data[2], int(data[3]), data[4]))
        # 统计流入网络流量
        # traffic_info[数据包个数，字节数]
        src_ip, src_port, dst_ip, dst_port, payload = data['srcIP'], data['srcPort'],data['dstIP'], data['dstPort'], data['payload']
        if src_ip in traffic_statistics:
            traffic_info = traffic_statistics[src_ip]
            traffic_info[0] += 1
            traffic_info[1] += len(payload)
            traffic_info[2] =dst_ip
        else:
            traffic_info = [1, len(payload),'']
            traffic_statistics[src_ip] = traffic_info
            traffic_info[2] = dst_ip

    # print('接受流量功能已就绪...')
    while True:
        data = s.recvfrom(65535)
        threading.Thread(target=process_recv_data, args=(data,)).start()


def createTimer():
    t = threading.Timer(interval, repeat)
    t.start()


def repeat():
    global traffic_statistics
    if not traffic_statistics:
        print('暂时无流量流入...')
    else:
        print('统计周期：%ds'%interval)
        total_traffic=sum([traffic_statistics[i][0] for i in traffic_statistics])
        for src_ip in traffic_statistics:
            info = traffic_statistics[src_ip]
            print('%s ---> %s 流入%d包，共%d字节，速率%.1fKB/s，占比%.1f%%' % (
                src_ip, info[2],info[0]*10000, info[1]*80000, (info[1]*80000/interval)/1024, info[0] / total_traffic*100))
        traffic_statistics = {}
    print('-'*100)
    createTimer()

def send_data2():
    while True:
        string='''1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM'''
        string=[i for i in string]
        randstr=''.join(random.choices(string,k=random.choice(range(1,40))))*random.choice(range(1,10))
        send_data('12345','20.1.2.5','54321',randstr)
        time.sleep(0.005)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((myEID, sm_user_port))

traffic_statistics = {}
interval = 3


