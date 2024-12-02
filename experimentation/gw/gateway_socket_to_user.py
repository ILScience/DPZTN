import socket
from zerotrustnetworkelement.gateway.exchange_key_with_user import *
from zerotrustnetworkelement.gateway.gw_configure import *
from zerotrustnetworkelement.gateway.user_register import *
from zerotrustnetworkelement.gateway.user_auth import *


def user_main():
    try:
        gateway_sk, gateway_pk, gateway_sk_sig, gateway_pk_sig, ecc1 = gw_user_key()
        # 与用户建立连接
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((gateway_ip, gateway_port))
        server_socket.listen(1)
        format_and_print(f'blockchain server listening on {gateway_ip}:{gateway_port}', '.', 'left')
        while True:
            try:
                user_socket, user_addr = server_socket.accept()
            except Exception as e:
                format_and_print(f'Error in Listening User:{e}', chr(0x00D7), 'left')
                continue

            # 交换密钥
            tt1, tt2, exchange_key_duration = pk_exchange(user_socket, gateway_pk, gateway_pk_sig)
            time_dict1 = {'tt1': tt1, 'tt2': tt2, 'exchange_key_duration': exchange_key_duration}
            user_hash_info = ''
            # 监听用户请求
            while True:
                try:
                    # 接收请求类型
                    request_type, tt3 = recv_with_header(user_socket)
                    request_start_time = get_timestamp()
                    format_and_print(f'Received message type: {request_type}', '-', 'center')
                    if request_type == b"USER REGISTRATION":
                        user_hash_info, uid, verify_result, tt4 = user_register(user_socket, ecc1)
                    elif request_type == b"USER AUTHENTICATION":

                    elif request_type == b"ACCESS":

                except Exception as e:
                    print(e)
                    pass

    except Exception as e:
        print(e)


if __name__ == '__main__':
    user_main()
