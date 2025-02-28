import threading
import psutil
from zerotrustnetworkelement.blockchain.gw_register import *
from zerotrustnetworkelement.blockchain.gw_auth import *
import socket
from zerotrustnetworkelement.blockchain.connection import *
from zerotrustnetworkelement.blockchain.bc_configure import *
from zerotrustnetworkelement.blockchain.user_register import *
from zerotrustnetworkelement.blockchain.bc_function import *
from zerotrustnetworkelement.blockchain.user_auth import *
from zerotrustnetworkelement.function import *

'''
时间复杂度：
    主要受 ECC 加密/解密、签名生成/验证、ZKP 验证以及网络 I/O 操作影响。
    总体时间复杂度为 O(n + m)，其中 n 是密钥位数，m 是消息大小。
空间复杂度：
    主要受密钥存储和消息存储的影响。
    总体空间复杂度为 O(n + m)，其中 n 是密钥位数，m 是消息大小。
'''


def gateway_main():
    # 建立与智能合约的链接
    loop, cli, org_admin = sc_connection(net_profile_path, 'org1.example.com')
    # 与网关建立连接
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((bc_ip, bc_port))
    server_socket.listen(5)
    format_and_print(f'blockchain server listening on {bc_ip}:{bc_port}', '.')
    while True:
        try:
            gw_socket, gw_addr = server_socket.accept()  # 监听网关
        except Exception as e:
            format_and_print(f'Error in Listening Gateway:{e}')
            # 结束进程
            continue

        while True:
            try:
                # 接收请求类型
                request_type, tt3 = recv_with_header(gw_socket)
                request_start_time = get_timestamp()
                format_and_print(f'Received message type: {request_type}', '-', 'center')
                # 如果接收到网关身份注册请求
                if request_type == b"GATEWAY REGISTRATION":
                    gid, tt1, tt2, tt3 = gw_register(gw_socket, loop, cli, org_admin, bc_ip)
                    # 上传网关信息
                    register_end_time = get_timestamp()
                    register_duration = register_end_time - request_start_time
                    time_dict1 = {'tt1': tt1, 'tt2': tt2, 'tt3': tt3, 'register_duration': register_duration}
                    append_to_json(gid, time_dict1)

                # 如果接收到网关身份认证请求
                elif request_type == b"GATEWAY AUTHENTICATION":
                    gid, tt4, tt5, tt6 = gw_auth(gw_socket, loop, cli, org_admin, bc_ip)
                    auth_end_time = get_timestamp()
                    auth_duration = auth_end_time - request_start_time
                    time_dict2 = {'tt4': tt4, 'tt5': tt5, 'tt6': tt6, 'auth_duration': auth_duration}
                    append_to_json(gid, time_dict2)

                # 如果接收到用户注册请求
                elif request_type == b"USER REGISTRATION":
                    user_id, tt8 = user_register(gw_socket, loop, cli, org_admin, bc_ip)
                    register_end_time = get_timestamp()
                    user_register_duration = register_end_time - request_start_time
                    time_dict4 = {'tt8': tt8, 'user_register_duration': user_register_duration}
                    append_to_json(user_id, time_dict4)

                elif request_type == b'USER AUTHENTICATION':
                    user_id, tt9, tt10, tt11 = user_auth(gw_socket, loop, cli, org_admin, bc_ip)
                    auth_end_time = get_timestamp()
                    user_auth_duration = auth_end_time - request_start_time
                    time_dict5 = {'tt9': tt9, 'tt10': tt10, 'tt11': tt11, 'user_auth_duration': user_auth_duration}
                    append_to_json(user_id, time_dict5)

            except KeyboardInterrupt as k:
                gw_socket.close()
                server_socket.close()
                print('0 KeyboardInterrupt:', k)
            except ValueError as v:
                print('0 ValueError:', v)
            except TypeError as t:
                print('0 TypeError:', t)
            except IndexError as i:
                print('0 IndexError:', i)
            except AttributeError as a:
                print('0 AttributeError:', a)
            except ConnectionError:
                continue


if __name__ == '__main__':
    # 获取当前进程
    process = psutil.Process()
    # 定义监控的时长（例如10秒）
    monitoring_duration = 20
    # 创建并启动监控线程
    monitor_thread = threading.Thread(target=monitor_resources,
                                      args=(process, "resource_usage.csv", monitoring_duration))
    monitor_thread.start()
    # 调用主任务
    gateway_main()
    '''
        每隔一段时间查询网关信誉值，
    '''
    # 等待监控线程完成
    monitor_thread.join()
