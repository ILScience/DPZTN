import socket
from zerotrustnetworkelement.user.user_configure import *
from zerotrustnetworkelement.user.user_register import *
from zerotrustnetworkelement.user.user_auth import *
import threading
import psutil
from zerotrustnetworkelement.user.user_access import *


# 1.用户注册
def user_register(user_socket, salt):
    register_start_time = get_timestamp()
    user_id, register_result, tt1, tt2, tt3 = user_reg(user_socket, salt)
    register_end_time = get_timestamp()
    user_register_time = register_end_time - register_start_time
    time_dict1 = {'tt1': tt1, 'tt2': tt2, 'tt3': tt3, 'user_register_time': user_register_time}
    append_to_json(user_id, time_dict1)
    return user_id, register_result


# 2.用户认证
def user_authentication(user_socket, user_id):
    # 用户身份认证
    auth_start_time = get_timestamp()
    auth_result, tt5, tt6 = user_auth(user_socket, user_id)
    auth_end_time = get_timestamp()
    user_auth_duration = auth_end_time - auth_start_time
    time_dict2 = {'tt5': tt5, 'tt6': tt6, 'user_auth_duration': user_auth_duration}
    append_to_json(user_id, time_dict2)
    return auth_result


def user_access(user_socket, user_id, pcap_file):
    access_start_time = get_timestamp()
    access_result = user_access(user_socket, user_id, pcap_file)
    access_end_time = get_timestamp()
    user_access_duration = access_end_time - access_start_time
    time_dict3 = {"user_access_duration": user_access_duration}
    append_to_json(user_id, time_dict3)


def user_main(salt, pcap_file):
    try:
        user_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建 socket 对象
        user_socket.bind((user_ip, user_port))  # 绑定ip,port
        user_socket.connect((gateway_ip, gateway_port))  # 连接到区块链服务器
        format_and_print(f"Connected to blockchain server at {gateway_ip}:{gateway_port} from {user_ip}:{user_port}",
                         '.', 'left')
        uid, reg_result = user_register(user_socket, salt)
        if reg_result:
            user_authentication(user_socket, uid)
            user_access(user_socket, uid, pcap_file)
            user_socket.close()
        user_socket.close()
    except KeyboardInterrupt:
        user_socket.close()
    except AttributeError as a:
        print(f'AttributeError: {a}')
    except Exception as e:  # 捕获其他异常
        user_socket.close()
        print(f'Unexpected error: {e}')


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
    user_main("001", './all_3h.pcap')
    # 等待监控线程完成
    monitor_thread.join()
