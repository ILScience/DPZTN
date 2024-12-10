from zerotrustnetworkelement.blockchain.bc_function import *
from zerotrustnetworkelement.blockchain.exchange_key import *


# 接收网关加密身份信息和网关签名
def receive_gateway_identity(client_socket, ecc, server_private_key, client_public_key):
    format_and_print('2.2 Start receiving gateway encrypted identities and gateway signatures', '.', 'left')
    try:
        data, transfer_time = recv_with_header(client_socket)
        message1 = convert_message(data, 'str')
        client_hash_info, client_sig_str = ecc.ecc_decrypt(server_private_key, client_public_key,
                                                           message1).split("||")  # 消息解密
        client_hash_info = convert_message(client_hash_info, 'bytes')  # 将网关身份加密消息，由str转换成bytes
        client_sig = convert_message(client_sig_str, 'SignedMessage')  # 将网关签名由str转换成SignedMessage

        format_and_print('2.2 Gateway encrypted identity information and gateway signature received successfully', '-',
                         'center')
        return client_hash_info, client_sig, transfer_time

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


# 生成gid，并返回gid注册状态查询结果
def generate_and_check_gid(client_hash_info):
    format_and_print('2.3 Start generating gid', '.', 'left')
    try:
        gateway_id = generate_gid(convert_message(client_hash_info, 'str'))  # 生成gid
        format_and_print('2.3 Complete gid generation', "-", "center")
        return gateway_id

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


# 给网关返回gid和区块链签名
def send_gid_and_signature(client_socket, gateway_id, ecc, server_sign_key, server_private_key, client_public_key):
    format_and_print('2.5 Start sending gid and blockchain signature to gateway', '.', 'left')
    try:
        server_signature = ecc.ecc_sign(server_sign_key, gateway_id.bytes)  # 生成区块链签名
        # 发送gid，区块链签名
        message2 = ecc.ecc_encrypt(server_private_key, client_public_key,
                                   f"{gateway_id}||{server_signature}")
        send_with_header(client_socket, convert_message(message2, 'bytes'))
        format_and_print('2.5 Complete gid and blockchain send', "-", "center")

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


# 网关身份注册
def gw_register(client_socket):
    format_and_print('2.Starting the Identity Enrollment Process', ':', 'left')
    try:
        server_private_key, server_public_key, server_sign_key, server_verify_key, ecc = bc_key()
        tt1, tt2, client_public_key, client_verify_key, exchange_key_duration = pk_exchange(client_socket,
                                                                                            server_public_key,
                                                                                            server_verify_key)  # 交换密钥
        time_dict1 = {'tt1': tt1, 'tt2': tt2, 'exchange_key_duration': exchange_key_duration}

        # 接收注册信息，并还原数据类型
        client_hash_info, client_sig, tt1 = receive_gateway_identity(client_socket, ecc, server_private_key,
                                                                     client_public_key)
        # 生成gid，并返回gid注册状态查询结果
        gateway_id = generate_and_check_gid(client_hash_info)

        folder_path = get_folder_path(str(gateway_id))
        if os.path.exists(folder_path):
            format_and_print(f'Gateway is registered', chr(0x00D7), 'left')
        else:
            # 创建文件夹
            os.makedirs(folder_path)
            save_key_to_file(server_public_key, 'pk_bc', folder_path)
            save_key_to_file(server_private_key, 'sk_bc', folder_path)
            save_key_to_file(server_verify_key, 'pk_sig_bc', folder_path)
            save_key_to_file(server_sign_key, 'sk_sig_bc', folder_path)
            save_key_to_file(client_public_key, 'pk_gw', folder_path)
            save_key_to_file(client_verify_key, 'pk_sig_gw', folder_path)

        append_to_json(gateway_id, time_dict1)
        format_and_print('2.4 Start verifying gateway signatures', '.', 'left')
        verify_result = ecc.ecc_verify(client_verify_key, client_sig)  # 验证网关签名
        if verify_result:
            format_and_print(f'2.4 {gateway_id} Signature Authentication Successful', '_', 'center')
            send_gid_and_signature(client_socket, gateway_id, ecc, server_sign_key, server_private_key,
                                   client_public_key)  # 发送gid和区块链签名
        else:
            format_and_print(f'2.4 Gateway signature verification failed', chr(0x00D7), 'left')
        format_and_print('2.Identity Registration Successful', "=", "center")
        return client_hash_info, gateway_id, verify_result, tt1

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
