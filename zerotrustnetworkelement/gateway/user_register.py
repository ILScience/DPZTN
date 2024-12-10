from zerotrustnetworkelement.encryption.ecdh import *
from zerotrustnetworkelement.gateway.exchange_key_with_user import *


# 2.2 接收用户加密身份信息和用户签名
def receive_user_info(client_socket, ecc, server_private_key, client_public_key):
    format_and_print('2.2 Start receiving user encrypted identities and user signatures', '.', 'left')
    try:
        data, transfer_time = recv_with_header(client_socket)
        message1 = convert_message(data, 'str')
        client_hash_info, client_sig_str = ecc.ecc_decrypt(server_private_key, client_public_key,
                                                           message1).split("||")  # 消息解密
        client_hash_info = convert_message(client_hash_info, 'bytes')  # 将用户身份加密消息，由str转换成bytes
        client_sig = convert_message(client_sig_str, 'SignedMessage')  # 将用户签名由str转换成SignedMessage
        format_and_print('2.2 Successful receipt of user information and user signature', '-', 'center')
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


# 2.3 验证用户签名
def verify_user_sign(ecc, client_verify_key, client_sig):
    format_and_print('2.3 Verify User Signature', '.', 'left')
    try:
        verify_result = ecc.ecc_verify(client_verify_key, client_sig)
        format_and_print('2.3 Complete user signature verification', '-', 'center')
        return verify_result
    except Exception as e:
        format_and_print(f'2.3 Error calling verify_user_sign():{e}', chr(0x00D7), 'left')


# 2.4 将gid和用户加密信息发送给区块链
def send_gid_and_uinfo(gateway_socket, client_hash_info, aes_key_to_bc, gid):
    format_and_print(f'Send gid and user identity information to the blockchain', '.', 'left')
    try:
        send_with_header(gateway_socket, b"USER REGISTRATION")  # 发送消息类型
        send_with_header(gateway_socket, convert_message(f'{gid}', 'bytes'))
        message2 = aes_encrypt(aes_key_to_bc, convert_message(f'{client_hash_info}', 'bytes'))
        send_with_header(gateway_socket, message2)
        format_and_print('2.4 Gid and user encrypted message sent.', '-', 'center')

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


# 2.5 接收并解析出uid
def recv_uid_from_bc(server_socket, aes_key_to_bc):
    format_and_print(f'2.5 Send gid and user identity information to the blockchain', '.', 'left')
    try:
        data, transfer_time = recv_with_header(server_socket)
        user_id = convert_message(convert_message(aes_decrypt(aes_key_to_bc, data), 'str'), 'UUID')
        format_and_print('2.5 Receive and parse out the uid.', '-', 'center')
        return user_id, transfer_time

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

# 2.6 生成网关签名,发送给用户
def generate_gateway_sign(ecc, gateway_sign_key, user_id, gateway_private_key, user_public_key, user_socket):
    format_and_print(f'2.5 Gateway signature being generated.', '.', 'left')
    try:
        gateway_signature = ecc.ecc_sign(gateway_sign_key, user_id.bytes)
        # 发送gid，区块链签名
        message2 = ecc.ecc_encrypt(gateway_private_key, user_public_key,
                                   f"{user_id}||{gateway_signature}")
        send_with_header(user_socket, convert_message(message2, 'bytes'))
        format_and_print('2.5 Receive and parse out the uid.', '-', 'center')
    except Exception as e:
        format_and_print(f'2.5 Error calling recv_uid_from_bc():{e}', chr(0x00D7), 'left')


# 2 用户注册流程
def user_register(gateway_socket, user_socket, gid):
    format_and_print(f'2. Start the user registration process.', ':', 'left')
    try:
        gateway_sk, gateway_pk, gateway_sk_sig, gateway_pk_sig, ecc = gw_user_key()
        # 交换密钥
        user_pk, user_sig_pk, tt_u1, tt_u2, exchange_key_duration = user_pk_exchange(user_socket,
                                                                                     gateway_pk,
                                                                                     gateway_pk_sig)
        time_dict1 = {'tt_u1': tt_u1, 'tt_u2': tt_u2, 'exchange_key_duration': exchange_key_duration}

        gateway_folder_path = get_folder_path(str(gid))
        sk_gw = load_key_from_file('sk_gw', gateway_folder_path)
        pk_bc = load_key_from_file('pk_bc', gateway_folder_path)
        aes_key = generate_aes_key(sk_gw, pk_bc)

        client_hash_info, client_sig, tt_u = receive_user_info(user_socket, ecc, gateway_sk, user_pk)
        verify_result = verify_user_sign(ecc, user_sig_pk, client_sig)
        if verify_result:
            send_gid_and_uinfo(gateway_socket, client_hash_info, aes_key, gid)
            user_id, tt_b = recv_uid_from_bc(gateway_socket, aes_key)

            user_folder_path = get_folder_path(str(user_id))
            if os.path.exists(user_folder_path):
                format_and_print(f'Gateway is registered', chr(0x00D7), 'left')
            else:
                # 创建文件夹
                os.makedirs(user_folder_path)
                save_key_to_file(gateway_pk, 'pk_gateway', user_folder_path)
                save_key_to_file(gateway_sk, 'sk_gateway', user_folder_path)
                save_key_to_file(gateway_pk_sig, 'pk_sig_gateway', user_folder_path)
                save_key_to_file(gateway_sk_sig, 'sk_sig_gateway', user_folder_path)
                save_key_to_file(user_pk, 'pk_user', user_folder_path)
                save_key_to_file(user_sig_pk, 'pk_sig_user', user_folder_path)

            append_to_json(user_id, time_dict1)

            generate_gateway_sign(ecc, gateway_sk_sig, user_id, gateway_sk, user_pk, user_socket)
            format_and_print('2. Identity Registration Successful', "=", "center")
            return user_id, tt_u, tt_b
        else:
            format_and_print(f'2.3 User Signature Verification Failure!', chr(0x00D7), 'left')

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
