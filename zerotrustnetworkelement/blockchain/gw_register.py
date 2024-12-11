from zerotrustnetworkelement.blockchain.bc_function import *
import cryptography.exceptions
from zerotrustnetworkelement.encryption.ecc import *
from zerotrustnetworkelement.function import *

'''可以放入function'''


# 1.1.生成区块链的对称密钥及公私钥
def generate_ecc_key():
    format_and_print('1.1.The ecc key pair being generated', ':')
    try:
        ecc = ECC()
        private_key, public_key = ecc.ecc_genkey()
        signing_key, verify_key = ecc.ecc_genkey_sign()
        format_and_print('1.1.The ecc key pair was successfully generated', '-', 'center')
        return private_key, public_key, signing_key, verify_key, ecc
    except ValueError as v:
        format_and_print(f"1.1.ValueError in generate_ecc_key(): {str(v)}")
    except TypeError as t:
        format_and_print(f"1.1.TypeError in generate_ecc_key(): {str(t)}")
    except cryptography.exceptions.InvalidSignature as c:
        format_and_print(f"1.1.InvalidSignature Error in generate_ecc_key(): {str(c)}")
    except Exception as e:
        format_and_print(f"1.1.Unexpected error occurred in generate_ecc_key(): {str(e)}")


# 1.2.公钥交换
def exchange_pk_with_gw(client_socket, server_public_key, server_verify_key):
    format_and_print('1.2.Exchanging Key', ':', 'left')
    try:
        send_with_header(client_socket, convert_message(server_public_key, 'bytes'))  # 发送区块链公钥
        send_with_header(client_socket, convert_message(server_verify_key, 'bytes'))  # 发送区块链认证密钥

        data, transfer_time1 = recv_with_header(client_socket)
        gateway_public_key = convert_message(data, 'PublicKey')  # 接收网关公钥
        data, transfer_time2 = recv_with_header(client_socket)
        gateway_verify_key = convert_message(data, 'VerifyKey')  # 接收网关认证密钥
        format_and_print('1.2.Key exchange successful', '-', 'center')
        return transfer_time1, transfer_time2, gateway_public_key, gateway_verify_key
    except ValueError as e:
        format_and_print(f'1.2.ValueError in exchange_pk_with_gw():{str(e)}')
    except TypeError as e:
        format_and_print(f'1.2.TypeError in exchange_pk_with_gw():{str(e)}')
    except Exception as e:
        format_and_print(f'1.2.Unexpected error in exchange_pk_with_gw():{str(e)}')


# 1.3.接收网关加密身份信息和网关签名
def recv_gw_identity_info(client_socket, ecc, server_private_key, client_public_key):
    format_and_print('1.3.Start receiving gateway encrypted identities and gateway signatures', '.', 'left')
    try:
        data, transfer_time = recv_with_header(client_socket)
        message1 = convert_message(data, 'str')
        client_hash_info, client_sig_str = ecc.ecc_decrypt(server_private_key, client_public_key, message1).split(
            "||")  # 消息解密
        client_hash_info = convert_message(client_hash_info, 'bytes')  # 将网关身份加密消息，由str转换成bytes
        client_sig = convert_message(client_sig_str, 'SignedMessage')  # 将网关签名由str转换成SignedMessage

        format_and_print('1.3.Gateway encrypted identity information and gateway signature received successfully', '-',
                         'center')
        return client_hash_info, client_sig, transfer_time

    except KeyboardInterrupt as k:
        format_and_print(f'1.3.KeyboardInterrupt in recv_gw_identity_info():{str(k)}')
    except Exception as e:
        format_and_print(f'1.3.Unexpected error in exchange_pk_with_gw():{str(e)}')


# 1.4.生成gid
def generate_gid(client_hash_info):
    format_and_print('1.4.Start generating gid', '.')
    try:
        gateway_id = generate_gid(convert_message(client_hash_info, 'str'))  # 生成gid
        format_and_print('1.4.Complete gid generation', "-", "center")
        return gateway_id

    except KeyboardInterrupt as k:
        format_and_print(f'1.4.KeyboardInterrupt in generate_gid():{str(k)}')
    except Exception as e:
        format_and_print(f'1.4.Unexpected error in generate_gid():{str(e)}')


# 1.5.创建以gid命名的文件夹存储公私钥
def save_bc_ecc_key(client_id, server_public_key, server_private_key, server_verify_key, server_sign_key,
                 client_public_key, client_verify_key):
    try:
        format_and_print('1.5.Start storing keys', '.')
        folder_path = get_folder_path(str(client_id))
        if os.path.exists(folder_path):
            format_and_print(f'1.5.Gateway is registered')
        else:
            # 创建文件夹
            os.makedirs(folder_path)
            save_key_to_file(server_public_key, 'pk_bc', folder_path)
            save_key_to_file(server_private_key, 'sk_bc', folder_path)
            save_key_to_file(server_verify_key, 'pk_sig_bc', folder_path)
            save_key_to_file(server_sign_key, 'sk_sig_bc', folder_path)
            save_key_to_file(client_public_key, 'pk_gw', folder_path)
            save_key_to_file(client_verify_key, 'pk_sig_gw', folder_path)
            format_and_print('1.5.The key is saved.', "-", "center")
    except Exception as e:
        format_and_print(f'1.5.Unexpected error in save_ecc_key():{str(e)}')


# 1.6.验证网关签名
def verify_client_sig(ecc, client_verify_key, client_sig):
    try:
        format_and_print('1.6.Start verifying gateway signatures', '.')
        verify_result = ecc.ecc_verify(client_verify_key, client_sig)  # 验证网关签名
        format_and_print('1.6.Gateway Signature Verification Successful', "-", "center")
        return verify_result
    except Exception as e:
        format_and_print(f'1.6.Unexpected error in verify_client_sig():{str(e)}')


# 1.7.给网关返回gid和区块链签名
def return_gid_and_signature(client_socket, client_id, ecc, server_sign_key, server_private_key, client_public_key):
    format_and_print('1.7. Start sending gid and blockchain signature to gateway', '.', 'left')
    try:
        server_signature = ecc.ecc_sign(server_sign_key, client_id.bytes)  # 生成区块链签名
        # 发送gid，区块链签名
        message2 = ecc.ecc_encrypt(server_private_key, client_public_key,
                                   f"{client_id}||{server_signature}")
        send_with_header(client_socket, convert_message(message2, 'bytes'))
        format_and_print('1.7.Complete gid and blockchain signature send', "-", "center")

    except Exception as e:
        format_and_print(f'1.7.Unexpected error in return_gid_and_signature():{str(e)}')


# 网关身份注册
def gw_register(client_socket):
    format_and_print('1.Initiate the gateway registration process', ':')
    try:
        # 1.1.生成区块链ecc密钥对
        server_private_key, server_public_key, server_sign_key, server_verify_key, bc_ecc = generate_ecc_key()
        # 1.2.与网关交换公钥
        tt1, tt2, client_public_key, client_verify_key = exchange_pk_with_gw(client_socket, server_public_key,
                                                                             server_verify_key)
        # 1.3.接收注册信息，并还原数据类型
        client_hash_info, client_sig, tt3 = (
            recv_gw_identity_info(client_socket, bc_ecc, server_private_key, client_public_key))
        # 1.4.生成gid，并返回gid注册状态查询结果
        client_id = generate_gid(client_hash_info)
        # 1.5.创建以gid命名的文件夹存储公私钥
        save_bc_ecc_key(client_id, server_public_key, server_private_key, server_verify_key, server_sign_key,
                     client_public_key, client_verify_key)
        # 1.6.验证网关签名
        client_sig_verify_result = verify_client_sig(bc_ecc, client_verify_key, client_sig)

        if client_sig_verify_result:
            # 1.7.返回区块链签名和gid
            return_gid_and_signature(client_socket, client_id, bc_ecc, server_sign_key, server_private_key,
                                     client_public_key)
        else:
            format_and_print(f'1.7 Gateway signature verification failed', chr(0x00D7), 'left')
        format_and_print('1.Gateway Registration Successful', "=", "center")
        return tt1, tt2, tt3, client_hash_info, client_id, client_sig_verify_result

    except Exception as e:
        format_and_print(f'1.Unexpected error in gw_register():{str(e)}')
