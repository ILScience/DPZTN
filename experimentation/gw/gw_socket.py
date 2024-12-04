from zerotrustnetworkelement.gateway.exchange_key_with_bc import *
from zerotrustnetworkelement.gateway.gw_info import *
from zerotrustnetworkelement.gateway.gw_register import *
from zerotrustnetworkelement.gateway.gw_auth import *
from gateway_socket_to_user import *
import socket
from zerotrustnetworkelement.gateway.gw_configure import *

# from zerotrustnetworkelement.gateway.exchange_key_with_user import *

'''
时间复杂度：
    主要由椭圆曲线加密操作、签名和加密解密操作决定，通常是 O(n)（椭圆曲线操作）或 O(n + k)，其中 n 是密钥的大小（通常是 256 位），k 是消息大小。
空间复杂度：
    主要存储公钥、私钥、签名和加密数据，通常是 O(n + k)。
'''


def gateway_main():
    try:
        # 生成网关信息
        gw_sk, gw_pk, gw_sk_sig, gw_pk_sig, ecc = gw_key()  # 初始化区块链密钥
        gw_info, gw_hash_info = gw_info_generate()  # 网关身份信息生成

        # 与区块链连接
        gw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建 socket 对象
        gw_socket.bind((gw_ip, gw_port))  # 绑定ip,port
        gw_socket.connect((bc_ip, bc_port))  # 连接到区块链服务器
        format_and_print(f"Connected to blockchain server at {bc_ip}:{bc_port} from {gw_ip}:{gw_port}", '.', 'left')

        # 交换公钥
        bc_pk, bc_pk_sig, tt1, tt2, exchange_key_duration = bc_pk_exchange(gw_socket, gw_pk, gw_pk_sig)
        time_dict1 = {'tt1': tt1, 'tt2': tt2, 'exchange_key_duration': exchange_key_duration}

        # 网关注册
        register_start_time = get_timestamp()
        gid, reg_result, tt3 = gw_register(gw_socket, ecc, gw_hash_info, bc_pk_sig)
        register_end_time = get_timestamp()
        register_duration = register_end_time - register_start_time
        time_dict2 = {'tt3': tt3, 'register_duration': register_duration}
        append_to_json(gid, time_dict1)
        append_to_json(gid, time_dict2)

        if reg_result is True:
            format_and_print('2.Identity Registration Successful', "=", "center")
            # 网关认证
            auth_start_time = get_timestamp()
            auth_result, tt4, tt5 = gw_auth(gw_socket, gid)
            auth_end_time = get_timestamp()
            auth_duration = auth_end_time - auth_start_time
            time_dict3 = {'tt4': tt4, 'tt5': tt5, 'auth_duration ': auth_duration}
            append_to_json(gid, time_dict3)

            if auth_result:
                format_and_print('3.Successful authentication', "=", "center")
                return auth_result, gid, gw_socket


            else:
                format_and_print('3.Authentication failure', chr(0x00D7), "center")

        else:
            format_and_print('2.Identity registration failure', chr(0x00D7), "center")


    except KeyboardInterrupt as k:
        print('KeyboardInterrupt:', k)
    except ValueError as v:
        print('ValueError:', v)
    except TypeError as t:
        print('TypeError:', t)
    except IndexError as i:
        print('IndexError:', i)
    except AttributeError as a:
        print('AttributeError:', a)


def user_main_zl(auth_result, gid, gateway_socket):
    try:
        if auth_result:
            user_main(gid, gateway_socket)
        else:
            print('gateway auth failed!')

    except KeyboardInterrupt as k:
        print('KeyboardInterrupt:', k)
    except ValueError as v:
        print('ValueError:', v)
    except TypeError as t:
        print('TypeError:', t)
    except IndexError as i:
        print('IndexError:', i)
    except AttributeError as a:
        print('AttributeError:', a)


if __name__ == '__main__':
    auth_result, gid, gw_socket = gateway_main()
    user_main_zl(auth_result, gid, gw_socket)
