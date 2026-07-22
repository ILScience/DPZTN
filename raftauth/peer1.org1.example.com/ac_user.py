import socket
import struct
import argparse
import random
import rsa
import hashlib
import base64
import time
import sys
import random
import threading
import uuid
import csv
import time
from Crypto.Cipher import AES
import argparse
import psutil
from configure import *


# ac_server_port=50000
# myEID=psutil.net_if_addrs()['eth2'][0].address
# gateway_EID={'20.1.1':'20.1.1.1','20.1.2':'20.1.2.4','20.1.3':'20.1.3.7'}[myEID[:-2]]


def add_to_16(value):
    while len(value) % 16 != 0:
        value += '\0'
    return str.encode(value)  # 返回bytes


def AES_encrypt(key, text):
    aes = AES.new(add_to_16(key), AES.MODE_ECB)  # 初始化加密器
    encrypt_aes = aes.encrypt(add_to_16(text))  # 先进行aes加密
    encrypted_text = str(base64.encodebytes(encrypt_aes), encoding='utf-8')  # 执行加密并转码返回bytes
    return encrypted_text


def AES_decrypt(key, text):
    aes = AES.new(add_to_16(key), AES.MODE_ECB)  # 初始化加密器
    base64_decrypted = base64.decodebytes(text.encode(encoding='utf-8'))  # 优先逆向解密base64成bytes
    decrypted_text = str(aes.decrypt(base64_decrypted), encoding='utf-8').replace('\0', '')  # 执行解密密并转码返回str
    return decrypted_text


def ac(SUPI='SUPI_test', resource='resource1', action='read', ip=gateway_EID, port=ac_server_port):
    # 请求连接网关，发送认证请求标志
    # SUPI = str(uuid.uuid3(uuid.NAMESPACE_DNS, SUPI))
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.connect((ip, port))
    connection.send(('abac++++++' + SUPI).encode('utf-8'))
    print('发送访问控制请求:', 'abac++++++' + SUPI)
    response = connection.recv(1024).decode('utf-8')
    if 'Error' in response:
        print(response)
        connection.close()
        print('-' * 150)
        return False
    else:
        K_SEAF = response
        print('取对称密钥K_SEAF:', K_SEAF)
        data = AES_encrypt(K_SEAF, (resource + '+++' + action))
        print('发送访问控制密文:', data,end='')
        connection.send(data.encode('utf-8'))
        print('等待决策结果...')
        data = connection.recv(1024).decode('utf-8')
        data = AES_decrypt(K_SEAF, data)
        if 'success' in data:
            print(data)
            connection.close()
            print('-' * 150)
            return data
        else:
            print(data)
            connection.close()
            print('-' * 150)
            return False


def resource_policy(*args):
    # 请求连接网关，发送策略操作表征
    try:
        data='++++++'.join(args)
    except:
        print('输入错误，请检查输入参数')
        return
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.connect((gateway_EID, ac_server_port))
    print('发送资源策略操作: ', args)
    connection.send(data.encode('utf-8'))
    response = connection.recv(65535).decode('utf-8')
    print('资源策略操作结果: ',response)
    print('-' * 150)


# def re_abac():
#     server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     server.bind(('192.168.16.6', 54321))
#     print('UDP Server %s:%d is ready' % ('192.168.16.6', 54321))
#     while True:
#         re_abac_user, _ = server.recvfrom(1024)
#         re_abac_user = re_abac_user.decode('utf-8')
#         re_abac_user = re_abac_user.split('+++')
#         print('重新访问控制用户：', re_abac_user)
#         print('-' * 150)
#         for user_SUPI in re_abac_user:
#             abac(user_SUPI, 'device_' + str(random.randint(0, 10)), random.choice(resource),
#                  random.choice(['read', 'write']),
#                  '192.168.200.4', 50000)
#         server.sendto('ok'.encode('utf-8'), ('192.168.200.4', 22222))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("a")
    parser.add_argument("b")
    args = parser.parse_args()

    supi = []
    resource = ["www.resource1.ip707.bjtu.cn"]
    total_time = []
    for i in range(int(args.a), int(args.b)):
        supi.append('SUPI_' + str(i))
    for i in range(int(args.a), int(args.b)):
        current = time.time()
        ac(supi[i], 'device_' + str(random.randint(0, 10)), random.choice(resource), random.choice(['read', 'write']),
             gateway_EID, ac_server_port)
        total_time.append(time.time() - current)
    print(total_time)
    print(sum(total_time) / 100)

# re_abac()

