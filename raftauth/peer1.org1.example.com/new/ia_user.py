# coding=gbk
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
from hashlib import sha256
import hmac
import hashlib
import argparse
import psutil
import json
from configure import *


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


def f1(K, RAND, sqn):
    encrypt_data = AES_encrypt(K, sqn + RAND)
    MAC = encrypt_data[:8]
    return MAC


def f2345(K, RAND):
    encrypt_data_1 = AES_encrypt(K, RAND)
    encrypt_data_2 = AES_encrypt(K, K)
    CK = encrypt_data_1[:16]
    IK = encrypt_data_1[16:24] + encrypt_data_2[16:24]
    AK = encrypt_data_2[:8]
    XRES = encrypt_data_2[8:16]
    return CK, IK, AK, XRES


def str_xor_str(str1, str2):
    orxstr = ""
    for i in range(0, len(str1) - 1):
        rst = ord(list(str1)[i]) ^ ord(list(str2)[i])
        orxstr = orxstr + chr(rst)
    return orxstr


def KDF(key, value):
    # hmac_sha256
    if type(key) == type('dcysb'):
        key = key.encode('utf-8')
    elif type(key) == type(b'dcysb'):
        pass
    else:
        print('KDF ERROR key', key)
        return ('0' * 16).encode('utf-8'), ('0' * 16).encode('utf-8')

    if type(value) == type('dcysb'):
        value = value.encode('utf-8')
    elif type(value) == type(b'dcysb'):
        pass
    else:
        print('KDF ERROR value', value)
        return ('0' * 16).encode('utf-8'), ('0' * 16).encode('utf-8')

    result = hmac.new(key, value, digestmod=hashlib.sha256).digest()
    CK_ = result[:16]
    IK_ = result[16:]
    return CK_, IK_


def generate_K_SEAF(key, value):
    s, b = KDF(key, value)
    bytes_K_SEAF = s + b
    # K_SEAF_mid=bytes_K_SEAF.decode('utf-8',errors='ignore')
    # K_SEAF=K_SEAF_mid*(32//len(K_SEAF_mid))
    # K_SEAF=K_SEAF.ljust(32,'0')
    K_SEAF = str(bytes_K_SEAF)[:32]
    return K_SEAF


def PRF(key, value):
    if type(key) == type('dcysb'):
        key = key.encode('utf-8')
    if type(value) == type('dcysb'):
        value = value.encode('utf-8')
    t1_a, t1_b = KDF(key, value + b'01')
    t1 = t1_a + t1_b
    t2_a, t2_b = KDF(key, t1 + value + b'02')
    t2 = t2_a + t2_b
    t3_a, t3_b = KDF(key, t2 + value + b'03')
    t3 = t3_a + t3_b
    t4_a, t4_b = KDF(key, t3 + value + b'04')
    t4 = t4_a + t4_b
    t5_a, t5_b = KDF(key, t4 + value + b'05')
    t5 = t5_a + t5_b
    t6_a, t6_b = KDF(key, t5 + value + b'06')
    t6 = t6_a + t6_b
    t7_a, t7_b = KDF(key, t6 + value + b'07')
    t7 = t7_a + t7_b
    return t1 + t2 + t3 + t4 + t5 + t6 + t7


# SUPI和K任意字符，sqn占8个字符，
def ia_register(SUPI='SUPI_test', sqn='sqn', K='Key', Role='admin', Cluster='ip707', Priviledge='8', ip=gateway_EID,
                port=ia_server_port):
    # SUPI=str(uuid.uuid3(uuid.NAMESPACE_DNS, SUPI))
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.connect((ip, port))
    connection.send('register'.encode('utf-8'))
    ok = connection.recv(1024)#接收数据大小
    # print(ok.decode('utf-8'))
    data = '+'.join([SUPI, sqn, K, Role, Cluster, Priviledge])
    print('发送注册参数: ', data)
    connection.send(data.encode('utf-8'))
    response = connection.recv(1024).decode('utf-8')
    print('接收注册结果: ', response)
    connection.close()
    print('-' * 150)


def ia_authen(SUPI='SUPI_test', sqn='sqn', K='Key', ip=gateway_EID, port=ia_server_port):
    # 请求连接网关，发送认证请求标志
    # SUPI = str(uuid.uuid3(uuid.NAMESPACE_DNS, SUPI))
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.connect((ip, port))
    connection.send('authen'.encode('utf-8'))
    response = connection.recv(1024).decode('utf-8')
    if 'Authen Failed' in response:
        print(response)
        connection.close()
        print('-' * 150)
        return 0
    # 接收网关公钥
    PublicKey = rsa.PublicKey.load_pkcs1(response.encode('utf-8'))
    # 选取随机数，用网关公钥加密生成SUCI,发送给网关
    R = str(random.choice(range(100, 999)))
    SUCI = rsa.encrypt((SUPI + '~' + R + '~' + K).encode('utf-8'), PublicKey)
    # print(SUCI)
    connection.send(SUCI)
    # print('flag_suci')
    print('发送SUCI: ', SUCI)
    # 判断SUPI和SNID是否验证授权成功
    response = connection.recv(1024).decode('utf-8')
    if response != 'success':
        if 'Authen Failed!' in response:
            print(response)
            connection.close()
            print('-' * 150)
            return 0
        else:
            connection.close()
            print('一小时内重复认证，无需再次执行5G-AKA认证流程，简单流程认证成功！')
            print('获取K_SEAF: ', response)
            print('-' * 150)
            return response
    # 接收RAND、AUTN、SNID
    data = connection.recv(1024).decode('utf-8')
    data = json.loads(data)
    RAND = data[0]
    AUTN = data[1]
    SNID = data[2]
    print('接收RAND、AUTN、SNID', data)
    # 计算XAUTN并比较
    CK, IK, AK, RES = f2345(K, RAND)
    XMAC = f1(K, RAND, sqn)
    XAUTN = str_xor_str(sqn, AK) + XMAC
    CK_, IK_ = KDF(CK + IK, (SNID + str_xor_str(sqn, AK)))
    # print('flag')
    print('对比XAUTN和AUTN：')
    print('XAUTN: ', XAUTN)
    print('AUTN : ', AUTN)
    if XAUTN != AUTN:
        print('用户对网关认证失败！')
        connection.send('Authen Failed! AUTN not equals!'.encode('utf-8'))
        connection.close()
        print('-' * 150)
        return 0
    # 生成RES并发送
    connection.send(RES.encode('utf-8'))
    print('生成RES并发送: ', RES)
    # print('No.7 and No.8')
    # 接收网关发来的XRES认证结果
    result = connection.recv(1024).decode('utf-8')
    if 'Authen Failed' in result:
        print('网关对用户认证失败！')
        connection.close()
        print('-' * 150)
        return
    # 双方认证成功，各自计算出密钥K_SEAF
    elif result == 'Authen success!':
        MK = PRF(IK_ + CK_, "EAP-AKA'" + SNID)
        EMSK = MK[144:208]
        K_AUSF = EMSK[-32:]
        K_SEAF = generate_K_SEAF(K_AUSF, SNID)
        print('生成K_SEAF: ', K_SEAF)
        connection.close()
        print('-' * 150)
        return K_SEAF
    else:
        print('ERROR')
        connection.close()
        print('-' * 150)
        return 0

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("request")
    parser.add_argument("a")
    parser.add_argument("b")
    args = parser.parse_args()

    supi = []
    sqn = []
    sharedkey = []
    total_time = []
    for i in range(int(args.a), int(args.b)):
        supi.append('SUPI_' + str(i))
        sqn.append('sqn' + str(i))
        sharedkey.append('sharedkey' + str(i))
    for i in range(int(args.a), int(args.b)):
        current = time.time()
        if args.request == 'a':
            ia_authen(supi[i], sqn[i], sharedkey[i], gateway_EID, ia_server_port)
        elif args.request == 'r':
            ia_register(supi[i], sqn[i], sharedkey[i], random.choice(['admin', 'manager']),
                        random.choice(['ip707', 'ip705']), str(random.randint(2, 6)), gateway_EID, ia_server_port)
        else:
            print('args error')
        total_time.append(time.time() - current)
    print(total_time)

    # re_authen()
