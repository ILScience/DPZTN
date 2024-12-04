from zerotrustnetworkelement.user.user_info import *
from zerotrustnetworkelement.user.exchange_key_with_gw import *
import socket
from zerotrustnetworkelement.user.user_configure import *
from zerotrustnetworkelement.user.user_register import *
from zerotrustnetworkelement.function import *


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

        # 网关注册
        register_start_time = get_timestamp()
        uid, tt3, tt4 = user_register(user_socket, ecc1, user_hash_info, gateway_pk_sig)
        register_end_time = get_timestamp()
        user_register_time = register_end_time - register_start_time
        time_dict2 = {'tt3': tt3, 'tt4': tt4, 'user_register_time': user_register_time}
        append_to_json(uid, time_dict1)
        append_to_json(uid, time_dict2)


    except Exception as e:
        print(e)


if __name__ == '__main__':
    user_main()
