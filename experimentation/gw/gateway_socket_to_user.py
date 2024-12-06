import socket
from zerotrustnetworkelement.gateway.exchange_key_with_user import *
from zerotrustnetworkelement.gateway.gw_configure import *
from zerotrustnetworkelement.gateway.user_register import *
from zerotrustnetworkelement.gateway.user_auth import *


def user_main(gid, gateway_socket):
    try:
        gateway_sk, gateway_pk, gateway_sk_sig, gateway_pk_sig, ecc1 = gw_user_key()
        # 与用户建立连接
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((gateway_ip, gateway_port))
        server_socket.listen(5)
        format_and_print(f'blockchain server listening on {gateway_ip}:{gateway_port}', '.', 'left')
        while True:
            user_socket, user_addr = server_socket.accept()
            # 交换密钥
            tt_u1, tt_u2, exchange_key_duration = user_pk_exchange(user_socket, gateway_pk, gateway_pk_sig)
            time_dict1 = {'tt_u1': tt_u1, 'tt_u2': tt_u2, 'exchange_key_duration': exchange_key_duration}
            # 监听用户请求
            while True:
                try:
                    # 接收请求类型
                    request_type, tt3 = recv_with_header(user_socket)
                    request_start_time = get_timestamp()
                    format_and_print(f'Received message type: {request_type}', '-', 'center')

                    if request_type == b"USER REGISTRATION":
                        uid, tt_u3, tt_b1 = user_register(gateway_socket, user_socket, ecc1, gid)
                        register_end_time = get_timestamp()
                        user_register_duration = register_end_time - request_start_time
                        time_dict2 = {'tt_u3': tt_u3, 'tt_b1': tt_b1, 'user_register_duration': user_register_duration}
                        append_to_json(uid, time_dict1)
                        append_to_json(uid, time_dict2)
                    elif request_type == b'USER AUTHENTICATION':
                        uid, aes_key_to_user, result, tt_u4, tt_b2, tt_u5, tt_u6 = user_auth(user_socket,
                                                                                             gateway_socket, gid)
                        auth_end_time = get_timestamp()
                        user_auth_duration = auth_end_time - request_start_time
                        time_dict3 = {'tt_u4': tt_u4, 'tt_b2': tt_b2, 'tt_u5': tt_u5, 'tt_u6': tt_u6,
                                      'user_auth_duration': user_auth_duration}
                        append_to_json(uid, time_dict3)

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
                except ConnectionError as a:
                    continue

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

