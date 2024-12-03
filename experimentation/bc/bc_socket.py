from zerotrustnetworkelement.blockchain.exchange_key import *
from zerotrustnetworkelement.blockchain.gw_register import *
from zerotrustnetworkelement.blockchain.gw_auth import *
from zerotrustnetworkelement.blockchain.connection import *
from zerotrustnetworkelement.function import *
from zerotrustnetworkelement.blockchain.bc_configure import *
from zerotrustnetworkelement.blockchain.bc_function import *
from zerotrustnetworkelement.blockchain.user_register import *

'''
时间复杂度：
    主要受 ECC 加密/解密、签名生成/验证、ZKP 验证以及网络 I/O 操作影响。
    总体时间复杂度为 O(n + m)，其中 n 是密钥位数，m 是消息大小。
空间复杂度：
    主要受密钥存储和消息存储的影响。
    总体空间复杂度为 O(n + m)，其中 n 是密钥位数，m 是消息大小。
'''


def gateway_main():
    # 生成区块链基本信息
    bc_sk, bc_pk, bc_sk_sig, bc_pk_sig, ecc = bc_key()
    # 与网关建立连接
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((bc_ip, bc_port))
    server_socket.listen(1)
    format_and_print(f'blockchain server listening on {bc_ip}:{bc_port}', '.', 'left')
    gw_hash_info = ''
    while True:
        try:
            gw_socket, gw_addr = server_socket.accept()  # 监听网关
        except Exception as e:
            format_and_print(f'Error in Listening Gateway:{e}', chr(0x00D7), 'left')
            # 结束进程
            continue

        # 交换密钥
        tt1, tt2, exchange_key_duration = pk_exchange(gw_socket, bc_pk, bc_pk_sig)
        time_dict1 = {'tt1': tt1, 'tt2': tt2, 'exchange_key_duration': exchange_key_duration}

        while True:
            try:
                # 接收请求类型
                request_type, tt3 = recv_with_header(gw_socket)
                request_start_time = get_timestamp()
                format_and_print(f'Received message type: {request_type}', '-', 'center')

                # 如果接收到网关身份注册请求
                if request_type == b"GATEWAY REGISTRATION":
                    gw_hash_info, gid, verify_result, tt4 = gw_register(gw_socket, ecc)
                    register_end_time = get_timestamp()
                    register_duration = register_end_time - request_start_time
                    time_dict2 = {'tt3': tt3, 'tt4': tt4, 'register_duration': register_duration}
                    append_to_json(gid, time_dict1)
                    append_to_json(gid, time_dict2)

                # 如果接收到网关身份认证请求
                elif request_type == b"GATEWAY AUTHENTICATION":
                    gid, aes_key, result, tt5, tt6, tt7 = gw_auth(gw_socket, gw_hash_info)
                    auth_end_time = get_timestamp()
                    auth_duration = auth_end_time - request_start_time
                    time_dict3 = {'tt3': tt3, 'tt5': tt5, 'tt6': tt6, 'tt7': tt7, 'auth_duration': auth_duration}
                    append_to_json(gid, time_dict3)
                    # 每次使用aes_key使用sk,pk重新生成
                    # 上传result

                # 如果接收到用户注册请求
                elif request_type == b"USER REGISTRATION":
                    user_register()




            except Exception as e:
                pass

            except KeyboardInterrupt:
                gw_socket.close()
                server_socket.close()
                pass


if __name__ == '__main__':
    gateway_main()
