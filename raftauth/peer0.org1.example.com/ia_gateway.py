# coding=gbk
import socket
import random
import rsa
import base64
import asyncio
from hfc.fabric import Client
from Crypto.Cipher import AES
import hashlib
import hmac
import nest_asyncio
nest_asyncio.apply()
from configure import *
import json


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


def generate_K_SEAF(key,value):
    s,b=KDF(key, value)
    bytes_K_SEAF=s+b
    # K_SEAF_mid=bytes_K_SEAF.decode('utf-8',errors='ignore')
    # K_SEAF=K_SEAF_mid*(32//len(K_SEAF_mid))
    # K_SEAF=K_SEAF.ljust(32,'0')
    K_SEAF=str(bytes_K_SEAF)[:32]
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


def ia_start(ip, port):
    # 开启服务器并监听请求
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ip, port))
    server.listen(1000)
    # global connection
    cli = Client(net_profile=net_profile_path)
    cli.new_channel('mychannel')
    loop = asyncio.get_event_loop()
    org1_admin = cli.get_user('org1.example.com', 'Admin')
    print('身份认证模块服务器端口No.%d已就绪...' % port)
    print('正在连接区块链...')
    #调用智能合约中用户注册函数
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org1_admin,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=['user_test', 'sqn', 'K', 'sb', 'sber', '-1'],
        cc_name='ia',
        fcn='register_user'
    ))
    print('区块链连接成功！')
    print('-'*150)
    while True:
        # 连接区块链
        # 取TCP连接请求
        connection, client_socket = server.accept()
        print('身份认证模块服务器%s:%d' % (ip, port), '建立TCP连接%s:%s' % client_socket)
        userEID=client_socket[0]
        # 判断是认证请求还是注册请求
        type_of_request = connection.recv(1024).decode('utf-8')
        # 处理认证请求
        if type_of_request == 'authen':
            # 取该网关的公钥私钥
            PrivateKey = loop.run_until_complete(cli.chaincode_query(
                requestor=org1_admin,
                channel_name='mychannel',
                peers=[ip_peer_map[ip]],
                args=['Gateway.' + ip],
                cc_name='ia',
                fcn='Get_AUSF_PrivateKey'
            ))
            PrivateKey = rsa.PrivateKey.load_pkcs1(PrivateKey.encode('utf-8'))
            # 把网关公钥发给设备
            PublicKey = loop.run_until_complete(cli.chaincode_query(
                requestor=org1_admin,
                channel_name='mychannel',
                peers=[ip_peer_map[ip]],
                args=['Gateway.' + ip],
                cc_name='ia',
                fcn='Get_AUSF_PublicKey'
            ))
            connection.send(PublicKey.encode('utf-8'))
            # 网关接收SUCI，解密出随机数R和SUPI
            SUCI = connection.recv(1024)
            request={'Request':'UID_Authen','Arguments':str(SUCI)}
            print('接收请求：',json.dumps(request))
            decrypt_data = rsa.decrypt(SUCI, PrivateKey).decode('utf-8')
            decrypt_data = decrypt_data.split('~')
            SUPI = decrypt_data[0]
            print('解密UID...')
            R = decrypt_data[1]
            recv_K = decrypt_data[2]
            # 检查SNID和SUPI是否被授权
            SNID = 'Gateway.' + ip
            response1 = loop.run_until_complete(cli.chaincode_query(
                requestor=org1_admin,
                channel_name='mychannel',
                peers=[ip_peer_map[ip]],
                args=[SNID],
                cc_name='ia',
                fcn='check_SNID'
            ))
            response2 = loop.run_until_complete(cli.chaincode_query(
                requestor=org1_admin,
                channel_name='mychannel',
                peers=[ip_peer_map[ip]],
                args=[SUPI],
                cc_name='ia',
                fcn='check_SUPI'
            ))
            if response1 == 'False' or response2 == 'False':
                print('认证失败！', response1, response2)
                connection.send('Authen Failed! Unauthorited SNID or unregisted SUPI'.encode('utf-8'))
                connection.close()
                print('-' * 150)
                continue
            #没有认证过或者距离上次认证超过一个小时
            if response2=='True':
                # print('No.2 and No.3')
                print('用户已注册: ',SUPI)
                print('接入网关已注册：', SNID)
                connection.send('success'.encode('utf-8'))
                # 生成随机质询RAND(16个字符)
                base_str = 'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz0123456789'
                RAND = ''.join([base_str[random.randint(0, len(base_str) - 1)] for i in range(16)])
                # 取SUPI的sqn和共享长期密钥K
                sqn_sharedKey = loop.run_until_complete(cli.chaincode_query(
                    requestor=org1_admin,
                    channel_name='mychannel',
                    peers=[ip_peer_map[ip]],
                    args=[SUPI],
                    cc_name='ia',
                    fcn='get_sqn_and_sharedKey'
                )).split('++++++')
                sqn = sqn_sharedKey[0]
                K = sqn_sharedKey[1]
                # print('获取K: ',K)
                # print('获取Sqn: ',sqn)
                # 计算各种参数(现在的f1和f2345还是简化版的)
                MAC = f1(K, RAND, sqn)  # MAC8个字符
                CK, IK, AK, XRES = f2345(K, RAND)  # CK16个字符，IK16个字符，AK8个字符，XRES8个字符
                AUTN = str_xor_str(sqn, AK) + MAC  # AUTN15或16个字符
                AV = RAND + XRES + CK + IK + AUTN  # AV好像用不到
                # 注意，CK_和IK_和AV_为字节类型                              #CK_16字节，IK_16字节
                CK_, IK_ = KDF(CK + IK, (SNID + str_xor_str(sqn, AK)))  # AV_也好像用不到
                AV_ = RAND.encode('utf-8') + XRES.encode('utf-8') + CK_ + IK_ + AUTN.encode('utf-8')
                connection.send(json.dumps([RAND,AUTN,SNID]).encode('utf-8'))
                # print('No.4 No.5 and No.6')
                print('生成认证向量AV: ',AV)
                print('生成认证代币AUTN: ', AUTN)
                print('转发认证参数，等待用户端响应...')
                # 接收设备端对XAUTN的比较结果
                result = connection.recv(1024).decode('utf-8')
                # print(result)
                if 'Authen Failed' in result:
                    print('用户对网关的认证失败!')
                    connection.close()
                    response = loop.run_until_complete(cli.chaincode_invoke(
                        requestor=org1_admin,
                        channel_name='mychannel',
                        peers=[ip_peer_map[ip]],
                        args=[SUPI, 'Fail','False',SNID,userEID],
                        cc_name='ia',
                        fcn='update_authen_result'
                    ))
                    response,txid=response.split('+++')
                    print('更新用户信息上链UI：',response)
                    print('交易哈希:', txid)
                    print('-' * 150)
                    continue
                # 比较设备端发来的RES和网关处的XRES
                HXRES = hmac.new('hashi-sha256-key'.encode('utf-8'), XRES.encode('utf-8'),
                                 digestmod=hashlib.sha256).digest()
                HRES = hmac.new('hashi-sha256-key'.encode('utf-8'), result.encode('utf-8'),
                                digestmod=hashlib.sha256).digest()
                print('对比响应内容：')
                print('XRES: ',HXRES)
                print('RES : ', HRES)
                if HXRES != HRES:
                    print('处理结果：网关对用户的认证失败！')
                    connection.send('Authen Failed! RES not equals!'.encode('utf-8'))
                    connection.close()
                    response = loop.run_until_complete(cli.chaincode_invoke(
                        requestor=org1_admin,
                        channel_name='mychannel',
                        peers=[ip_peer_map[ip]],
                        args=[SUPI, 'Fail','False',SNID,userEID],
                        cc_name='ia',
                        fcn='update_authen_result'
                    ))
                    response,txid=response.split('+++')
                    print('更新用户信息上链UI：',response)
                    print('交易哈希:', txid)
                    print('-' * 150)
                    continue
                # 双方认证成功，各自计算出密钥K_SEAF
                MK = PRF(IK_ + CK_, "EAP-AKA'" + SNID)
                EMSK = MK[144:208]
                K_AUSF = EMSK[-32:]
                K_SEAF = generate_K_SEAF(K_AUSF,SNID)
                connection.send('Authen success!'.encode('utf-8'))
                # print('生成K_AUSF: ', K_AUSF)
                print('计算对称密钥SK：', K_SEAF)
                print('处理结果：用户和网关双向认证成功！')
                response = loop.run_until_complete(cli.chaincode_invoke(
                    requestor=org1_admin,
                    channel_name='mychannel',
                    peers=[ip_peer_map[ip]],
                    args=[SUPI, 'Success',K_SEAF,SNID,userEID],
                    cc_name='ia',
                    fcn='update_authen_result'
                ))
                connection.close()
                response, txid = response.split('+++')
                print('更新用户信息上链UI：', response)
                print('交易哈希:', txid)
                print('-' * 150)
                continue
            #一小时内再次认证
            else:
                sqn_sharedKey = loop.run_until_complete(cli.chaincode_query(
                    requestor=org1_admin,
                    channel_name='mychannel',
                    peers=[ip_peer_map[ip]],
                    args=[SUPI],
                    cc_name='ia',
                    fcn='get_sqn_and_sharedKey'
                )).split('++++++')
                K = sqn_sharedKey[1]
                print('一小时内重复认证，执行简单认证流程!')
                print('核对用户密钥UK：')
                print('expected UK：', K)
                print('received UK：', recv_K)
                # print('获取对称密钥SK：', response2)
                if K!=recv_K:
                    print('处理结果：用户密钥错误，认证失败！')
                    response = loop.run_until_complete(cli.chaincode_invoke(
                        requestor=org1_admin,
                        channel_name='mychannel',
                        peers=[ip_peer_map[ip]],
                        args=[SUPI, 'Fail', 'False', SNID, userEID],
                        cc_name='ia',
                        fcn='update_authen_result'
                    ))
                    connection.send('Authen Failed! UK incorrect!'.encode('utf-8'))
                    connection.close()
                else:
                    print('处理结果：用户密钥正确，认证成功！')
                    response = loop.run_until_complete(cli.chaincode_invoke(
                        requestor=org1_admin,
                        channel_name='mychannel',
                        peers=[ip_peer_map[ip]],
                        args=[SUPI, 'Success', response2, SNID, userEID],
                        cc_name='ia',
                        fcn='update_authen_result'
                    ))
                    connection.send(response2.encode('utf-8'))
                    connection.close()
                print('-' * 150)
                continue
        # 处理注册请求
        elif type_of_request == 'register':
            connection.send('ok'.encode('utf-8'))
            data = connection.recv(1024).decode('utf-8')
            data = data.split('+')
            SUPI = data[0]
            sqn = data[1]
            K = data[2]
            Role = data[3]
            Cluster = data[4]
            Priviledge = data[5]
            request={'Request':'UID_Rgister','Arguments':'   '.join([SUPI,sqn,K,Role,Cluster,Priviledge])}
            print('接收请求：',json.dumps(request))
            response = loop.run_until_complete(cli.chaincode_invoke(
                requestor=org1_admin,
                channel_name='mychannel',
                peers=[ip_peer_map[ip]],
                args=[SUPI, sqn, K, Role, Cluster, Priviledge],
                cc_name='ia',
                fcn='register_user'
            ))
            response,txid=response.split('+++')
            if 'error' in response:
                print('处理结果：注册失败！')
            else:
                print('处理结果：注册成功！')
                print('存储用户信息UI上链：',response)
            print('交易哈希：',txid)
            connection.send(response.encode('utf-8'))
            connection.close()
            print('-' * 150)
            continue
        # 处理异常请求
        else:
            print('输入参数错误！')
            connection.send('Authen Failed! Wrong Arugument'.encode('utf-8'))
            connection.close()
            print('-' * 150)
            continue


if __name__ == '__main__':
    ia_start(myEID, ia_server_port)
