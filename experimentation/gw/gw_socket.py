from zerotrustnetworkelement.gateway.gw_register import *
from zerotrustnetworkelement.gateway.gw_auth import *
import socket
from zerotrustnetworkelement.gateway.gw_configure import *
import threading
import psutil
from zerotrustnetworkelement.gateway.user_register import *
from zerotrustnetworkelement.gateway.user_auth import *

'''
时间复杂度：
    主要由椭圆曲线加密操作、签名和加密解密操作决定，通常是 O(n)（椭圆曲线操作）或 O(n + k)，其中 n 是密钥的大小（通常是 256 位），k 是消息大小。
空间复杂度：
    主要存储公钥、私钥、签名和加密数据，通常是 O(n + k)。
'''


# 1.网关注册
def gateway_register(gw_socket):
    register_start_time = get_timestamp()
    gw_id, reg_result, tt1, tt2, tt3 = gw_register(gw_socket)
    register_end_time = get_timestamp()
    register_duration = register_end_time - register_start_time
    time_dict1 = {'tt1': tt1, 'tt2': tt2, 'tt3': tt3, 'register_duration': register_duration}
    append_to_json(gw_id, time_dict1)
    return gw_id, reg_result


# 2.网关认证
def gateway_auth(gw_socket, gw_id):
    format_and_print('1.Identity Registration Successful', "=", "center")
    # 网关认证
    auth_start_time = get_timestamp()
    authentication_result, tt4, tt5 = gw_auth(gw_socket, gw_id)
    auth_end_time = get_timestamp()
    auth_duration = auth_end_time - auth_start_time
    time_dict2 = {'tt4': tt4, 'tt5': tt5, 'auth_duration ': auth_duration}
    append_to_json(gw_id, time_dict2)
    return authentication_result


def gateway_main():
    try:
        # 与区块链连接
        gw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建 socket 对象
        gw_socket.bind((gw_ip, gw_port))  # 绑定ip,port
        gw_socket.connect((bc_ip, bc_port))  # 连接到区块链服务器
        format_and_print(f"Connected to blockchain server at {bc_ip}:{bc_port} from {gw_ip}:{gw_port}", '.', 'left')
        # 网关注册
        gw_id, reg_result = gateway_register(gw_socket)
        # 网关认证
        authentication_result = gateway_auth(gw_socket, gw_id)

        if authentication_result:
            format_and_print('3.Successful authentication', "=", "center")
            return authentication_result, gw_id, gw_socket
        else:
            format_and_print('3.Authentication failure')
    except Exception as e:
        format_and_print(f'Error calling gateway_main():{e}')


def user_main(gw_socket, gw_id):
    try:
        # 与用户建立连接
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((gateway_ip, gateway_port))
        server_socket.listen(5)
        format_and_print(f'blockchain server listening on {gateway_ip}:{gateway_port}', '.', 'left')
        while True:
            user_socket, user_addr = server_socket.accept()
            # 监听用户请求
            while True:
                try:
                    # 接收请求类型
                    request_type, tt3 = recv_with_header(user_socket)
                    request_start_time = get_timestamp()
                    format_and_print(f'Received message type: {request_type}', '-', 'center')

                    if request_type == b"USER REGISTRATION":
                        user_id, tt_u1, tt_u2, tt_u3, tt_b1 = user_register(gw_socket, user_socket, gw_id)
                        register_end_time = get_timestamp()
                        user_register_duration = register_end_time - request_start_time
                        time_dict3 = {'tt_u1': tt_u1, 'tt_u2': tt_u2, 'tt_u3': tt_u3, 'tt_b1': tt_b1,
                                      'user_register_duration': user_register_duration}
                        append_to_json(user_id, time_dict3)
                    elif request_type == b'USER AUTHENTICATION':
                        user_id, aes_key_to_user, result, tt_u4, tt_b2, tt_u5, tt_u6 = user_auth(user_socket,
                                                                                                 gw_socket, gw_id)
                        auth_end_time = get_timestamp()
                        user_auth_duration = auth_end_time - request_start_time
                        time_dict4 = {'tt_u4': tt_u4, 'tt_b2': tt_b2, 'tt_u5': tt_u5, 'tt_u6': tt_u6,
                                      'user_auth_duration': user_auth_duration}
                        append_to_json(user_id, time_dict4)

                except KeyboardInterrupt as k:
                    print('KeyboardInterrupt:', k)
                except ConnectionError:
                    continue
                except Exception as e:
                    format_and_print(f'Error calling user_main():{e}')

    except KeyboardInterrupt as k:
        print('KeyboardInterrupt:', k)
    except AttributeError as a:
        print('AttributeError:', a)
    except Exception as e:
        format_and_print(f'Error calling user_main():{e}')


if __name__ == '__main__':
    # 获取当前进程
    process = psutil.Process()
    # 定义监控的时长（例如10秒）
    monitoring_duration = 15
    # 创建并启动监控线程
    monitor_thread = threading.Thread(target=monitor_resources,
                                      args=(process, "resource_usage.csv", monitoring_duration))
    monitor_thread.start()
    # 调用主任务
    auth_result, gid, gateway_socket = gateway_main()
    user_main(gateway_socket, gid)
    # 等待监控线程完成
    monitor_thread.join()
