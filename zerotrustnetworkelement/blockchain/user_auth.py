from zerotrustnetworkelement.function import *
from zerotrustnetworkelement.encryption.ecdh import *


# 3.1 接收网关gid和用户uid
def recv_gw_gid(client_socket, aes_key):
    format_and_print('3.1 Start receiving gateway gid', '.', 'left')
    try:
        data, transfer_time = recv_with_header(client_socket)
        gateway_id, user_id = convert_message(aes_decrypt(aes_key, data), 'str').split('||')
        gateway_id = convert_message(gateway_id, 'UUID')
        user_id = convert_message(user_id, 'UUID')
        format_and_print('3.1.Received gateway gid successfully', "_", "center")
        return gateway_id, user_id, transfer_time

    except KeyboardInterrupt as k:
        print('3.3 KeyboardInterrupt:', k)
    except ValueError as v:
        print('3.3 ValueError:', v)
    except TypeError as t:
        print('3.3 TypeError:', t)
    except IndexError as i:
        print('3.3 IndexError:', i)
    except AttributeError as a:
        print('3.3 AttributeError:', a)
    except FileExistsError as f:
        print('3.3 FileExistsError:', f)


# 3.2 加载密钥
def load_auth_key(client_socket, user_hash_info):
    format_and_print('3.2 Start searching for keys required for authentication', '.', 'left')
    try:
        data, transfer_time = recv_with_header(client_socket)
        gid = convert_message(data, 'UUID')
        gateway_folder_path = get_folder_path(str(gid))
        # 查询之前的网关公钥，区块链公钥
        blockchain_public_key = load_key_from_file('pk_bc', gateway_folder_path)
        blockchain_private_key = load_key_from_file('sk_bc', gateway_folder_path)
        blockchain_verify_key = load_key_from_file('pk_sig_bc', gateway_folder_path)
        blockchain_sign_key = load_key_from_file('sk_sig_bc', gateway_folder_path)
        gateway_public_key = load_key_from_file('pk_gw', gateway_folder_path)
        gateway_verify_key = load_key_from_file('pk_sig_gw', gateway_folder_path)
        # 加载用户公钥反馈给网关
        user_hash_info = convert_message(user_hash_info, 'bytes')
        aes_key = generate_aes_key(blockchain_private_key, gateway_public_key)
        format_and_print('3.2 Key required for successful query authentication', "_", "center")
        return (blockchain_public_key, blockchain_private_key, blockchain_verify_key, blockchain_sign_key,
                gateway_public_key, gateway_verify_key, user_hash_info, aes_key)

    except KeyboardInterrupt as k:
        print('3.2 KeyboardInterrupt:', k)
    except ValueError as v:
        print('3.2 ValueError:', v)
    except TypeError as t:
        print('3.2 TypeError:', t)
    except IndexError as i:
        print('3.2 IndexError:', i)
    except AttributeError as a:
        print('3.2 AttributeError:', a)
    except FileExistsError as f:
        print('3.2 FileExistsError:', f)


# 3.3 将用户信息返回给网关
def send_user_info(gateway_socket, user_hash_info, aes_key):
    format_and_print('3.3 Start returning user information', '.', 'left')
    try:
        print(user_hash_info)
        print(type(user_hash_info))
        message = aes_encrypt(aes_key, user_hash_info)
        print(message)
        send_with_header(gateway_socket, message)
        format_and_print('3.3 User information returned', "_", "center")

    except KeyboardInterrupt as k:
        print('3.3 KeyboardInterrupt:', k)
    except ValueError as v:
        print('3.3 ValueError:', v)
    except TypeError as t:
        print('3.3 TypeError:', t)
    except IndexError as i:
        print('3.3 IndexError:', i)
    except AttributeError as a:
        print('3.3 AttributeError:', a)
    except FileExistsError as f:
        print('3.3 FileExistsError:', f)


# 3.4 接收网关传回的注册结果
def recv_auth_result(gateway_socket):
    format_and_print('3.4 Start receiving auth result', '.', 'left')
    try:
        data, transfer_time = recv_with_header(gateway_socket)
        auth_result = convert_message(data, 'str')
        format_and_print('3.4 Received auth result', "_", "center")
        return auth_result, transfer_time

    except KeyboardInterrupt as k:
        print('3.4 KeyboardInterrupt:', k)
    except ValueError as v:
        print('3.4 ValueError:', v)
    except TypeError as t:
        print('3.4 TypeError:', t)
    except IndexError as i:
        print('3.4 IndexError:', i)
    except AttributeError as a:
        print('3.4 AttributeError:', a)
    except FileExistsError as f:
        print('3.4 FileExistsError:', f)


# 3 网关认证
def user_auth(gateway_socket, user_hash_info):
    format_and_print('3. Starting the authentication process', ':', 'left')
    try:
        (blockchain_public_key, blockchain_private_key, blockchain_verify_key, blockchain_sign_key,
         gateway_public_key, gateway_verify_key, user_hash_info, aes_key) = load_auth_key(gateway_socket,
                                                                                          user_hash_info)
        gateway_id, user_id, tt1 = recv_gw_gid(gateway_socket, aes_key)
        send_user_info(gateway_socket, user_hash_info, aes_key)
        auth_result, tt2 = recv_auth_result(gateway_socket)
        format_and_print('3. Auth success', "=", "center")
        return user_id, aes_key, tt1, auth_result, tt2

    except KeyboardInterrupt as k:
        print('3 KeyboardInterrupt:', k)
    except ValueError as v:
        print('3 ValueError:', v)
    except TypeError as t:
        print('3 TypeError:', t)
    except IndexError as i:
        print('3 IndexError:', i)
    except AttributeError as a:
        print('3 AttributeError:', a)
    except FileExistsError as f:
        print('3 FileExistsError:', f)
