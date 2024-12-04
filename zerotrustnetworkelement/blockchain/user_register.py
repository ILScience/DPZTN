from zerotrustnetworkelement.function import *
from zerotrustnetworkelement.encryption.ecdh import *
from zerotrustnetworkelement.blockchain.bc_function import *


# 2.1 加载密钥
def load_key():
    format_and_print('2.1 Loading the required key for registration', '.', 'left')
    try:
        server_private_key = load_key_from_file("sk_bc")  # 加载区块链私钥
        client_public_key = load_key_from_file('pk_gw')  # 加载网关公钥
        format_and_print('2.1 Key loaded successfully', '-', 'center')
        return server_private_key, client_public_key

    except KeyboardInterrupt as k:
        print('2.1 KeyboardInterrupt:', k)
    except ValueError as v:
        print('2.1 ValueError:', v)
    except TypeError as t:
        print('2.1 TypeError:', t)
    except IndexError as i:
        print('2.1 IndexError:', i)
    except AttributeError as a:
        print('2.1 AttributeError:', a)
    except FileExistsError as f:
        print('2.1 FileExistsError:', f)


# 2.2接收用户加密消息和gid，验证gid状态，生成uid
def receive_user_identity(client_socket, server_private_key):
    format_and_print('2.2 Start receiving user encrypted identities and user signatures', '.', 'left')
    try:
        client_public_key = load_key_from_file('pk_gw')  # 加载网关公钥

        aes_key = generate_aes_key(server_private_key, client_public_key)  # 生成aes密钥

        data, transfer_time = recv_with_header(client_socket)
        gateway_id, user_hash_info = convert_message(aes_decrypt(aes_key, data), 'str').split("||")  # 消息解密
        user_id = generate_gid(user_hash_info)  # 将用户身份加密消息，由str转换成bytes

        format_and_print('2.2 User encrypted identity information and user signature received successfully', '-',
                         'center')
        return user_hash_info, user_id, transfer_time

    except KeyboardInterrupt as k:
        print('2.2 KeyboardInterrupt:', k)
    except ValueError as v:
        print('2.2 ValueError:', v)
    except TypeError as t:
        print('2.2 TypeError:', t)
    except IndexError as i:
        print('2.2 IndexError:', i)
    except AttributeError as a:
        print('2.2 AttributeError:', a)


def send_uid_to_gateway(server_private_key, client_public_key, user_id, client_socket):
    format_and_print('2.3 Start sending uid', '.', 'left')
    try:
        aes_key = generate_aes_key(server_private_key, client_public_key)
        message3 = aes_encrypt(aes_key, convert_message(f'{user_id}', 'bytes'))
        send_with_header(client_socket, message3)
        format_and_print('2.3 Send uid over.', '-', 'center')

    except KeyboardInterrupt as k:
        print('2.3 KeyboardInterrupt:', k)
    except ValueError as v:
        print('2.3 ValueError:', v)
    except TypeError as t:
        print('2.3 TypeError:', t)
    except IndexError as i:
        print('2.3 IndexError:', i)
    except AttributeError as a:
        print('2.3 AttributeError:', a)


def user_register(client_socket):
    try:
        server_private_key, client_public_key = load_key()
        user_hash_info, uid, tt1 = receive_user_identity(client_socket, server_private_key)
        send_uid_to_gateway(server_private_key, client_public_key, uid, client_socket)
        return user_hash_info, uid, tt1

    except KeyboardInterrupt as k:
        print('2 KeyboardInterrupt:', k)
    except ValueError as v:
        print('2 ValueError:', v)
    except TypeError as t:
        print('2 TypeError:', t)
    except IndexError as i:
        print('2 IndexError:', i)
    except AttributeError as a:
        print('2 AttributeError:', a)
