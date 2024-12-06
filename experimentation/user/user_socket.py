from zerotrustnetworkelement.user.exchange_key_with_gw import *
import socket
from zerotrustnetworkelement.user.user_configure import *
from zerotrustnetworkelement.user.user_register import *
from zerotrustnetworkelement.user.user_auth import *
from zerotrustnetworkelement.user.user_info import *
from zerotrustnetworkelement.function import *
import threading
import psutil


def user_main():
    try:
        user_hash_info = user_info_generate()
        user_sk, user_pk, user_sk_sig, user_pk_sig, ecc1 = user_key()

        user_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建 socket 对象
        user_socket.bind((user_ip, user_port))  # 绑定ip,port
        user_socket.connect((gateway_ip, gateway_port))  # 连接到区块链服务器
        format_and_print(f"Connected to blockchain server at {gateway_ip}:{gateway_port} from {user_ip}:{user_port}",
                         '.', 'left')
        # 交换公钥
        gateway_pk, gateway_pk_sig, tt1, tt2, exchange_key_duration = pk_exchange(user_socket, user_pk, user_pk_sig)
        time_dict1 = {'tt1': tt1, 'tt2': tt2, 'exchange_key_duration': exchange_key_duration}

        # 用户注册
        register_start_time = get_timestamp()
        uid, reg_result, tt3 = user_register(user_socket, ecc1, user_hash_info, gateway_pk_sig)
        register_end_time = get_timestamp()
        user_register_time = register_end_time - register_start_time
        time_dict2 = {'tt3': tt3, 'user_register_time': user_register_time}
        append_to_json(uid, time_dict1)
        append_to_json(uid, time_dict2)
        if reg_result:
            # 用户身份认证
            auth_start_time = get_timestamp()
            auth_result, tt5, tt6 = user_auth(user_socket, uid)
            auth_end_time = get_timestamp()
            user_auth_duration = auth_end_time - auth_start_time
            time_dict3 = {'tt5': tt5, 'tt6': tt6, 'user_auth_duration': user_auth_duration}
            append_to_json(uid, time_dict3)
        else:
            print('Failed to register')

    except KeyboardInterrupt as k:
        print(f'KeyboardInterrupt: {k}')
    except ValueError as v:
        print(f'ValueError: {v}')
    except TypeError as t:
        print(f'TypeError: {t}')
    except IndexError as i:
        print(f'IndexError: {i}')
    except AttributeError as a:
        print(f'AttributeError: {a}')
    except Exception as e:  # 捕获其他异常
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
    user_main()
    # 等待监控线程完成
    monitor_thread.join()
