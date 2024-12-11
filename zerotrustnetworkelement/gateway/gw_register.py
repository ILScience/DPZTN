from zerotrustnetworkelement.encryption.ecc import *
from zerotrustnetworkelement.gateway.gw_function import *
from zerotrustnetworkelement.encryption.myhash import *
from zerotrustnetworkelement.function import *


# 1.1.生成网关身份信息
def gw_info_generate():
    format_and_print('Gateway identity information being generated', '.')
    try:
        ip, client_info = get_network_info()  # 生成网关信息gw_Info
        client_hash_info = hash_encrypt(convert_message(client_info, 'str'))  # 对网关身份信息进行加密
        format_and_print('Gateway identity information generated', '-', 'center')
        return client_hash_info
    except Exception as e:
        format_and_print(f'1.1.Error calling gw_info_generate():{e}')


# 1.2.生成网关ecc密钥对
def generate_ecc_key():
    format_and_print('1.2.The ecc key pair being generated', ':')
    try:
        ecc = ECC()
        private_key, public_key = ecc.ecc_genkey()
        signing_key, verify_key = ecc.ecc_genkey_sign()
        format_and_print('1.2.The ecc key pair was successfully generated', '-', 'center')
        return private_key, public_key, signing_key, verify_key, ecc
    except ValueError as v:
        format_and_print(f"1.2.ValueError in generate_ecc_key(): {str(v)}")
    except TypeError as t:
        format_and_print(f"1.2.TypeError in generate_ecc_key(): {str(t)}")
    except Exception as e:
        format_and_print(f"1.2.Unexpected error occurred in generate_ecc_key(): {str(e)}")


# 1.3.与区块链建立连接并交换公钥
def bc_pk_exchange(client_socket, client_public_key, client_verify_key):
    format_and_print('1.3.Start exchanging ecc key pairs with the blockchain', '.', 'left')
    try:
        data, transfer_time1 = recv_with_header(client_socket)
        server_public_key = convert_message(data, 'PublicKey')  # 接收区块链公钥
        data, transfer_time2 = recv_with_header(client_socket)
        server_verify_key = convert_message(data, 'VerifyKey')  # 接收区块链验证公钥

        send_with_header(client_socket, convert_message(client_public_key, 'bytes'))  # 发送网关公钥
        send_with_header(client_socket, convert_message(client_verify_key, 'bytes'))

        format_and_print('1.3.Complete ecc key pair exchange with blockchain', '-', 'center')
        return server_public_key, server_verify_key, transfer_time1, transfer_time2
    except Exception as e:
        format_and_print(f"1.3.Unexpected error occurred in bc_pk_exchange(): {str(e)}")


# 1.4.发送网关签名和注册信息
def sign_encrypt_and_send(ecc, client_sign_key, client_hash_info, client_private_key, server_public_key, client_socket):
    format_and_print('1.4.Start generating gateway signatures and send them to the blockchain', '.')
    try:
        # 生成签名
        client_sig = ecc.ecc_sign(client_sign_key, client_hash_info)
        # 加密消息
        message1 = ecc.ecc_encrypt(client_private_key, server_public_key, f"{client_hash_info}||{client_sig}")
        # 发送消息
        send_with_header(client_socket, convert_message(message1, 'bytes'))
        format_and_print("1.4.Signed and encrypted message sent successfully", "-", "center")
    except Exception as e:
        # 捕获异常并打印错误信息
        format_and_print(f'1.4.Error calling sign_encrypt_and_send():{e}')


# 1.5.接收区块链签名和gid
def decrypt_and_verify_data(client_socket, ecc, client_private_key, server_public_key):
    format_and_print('1.5.Start receiving blockchain signatures and verify', '.')
    try:
        data, transfer_time = recv_with_header(client_socket)
        message2 = convert_message(data, 'str')  # 接收加密消息
        decrypted_message = ecc.ecc_decrypt(client_private_key, server_public_key, message2)  # 解密消息
        client_id_str, server_sig_str = decrypted_message.split(
            "||")  # 解析消息

        # 转换数据类型
        client_id = convert_message(client_id_str, 'UUID')  # 转换为 UUID
        server_signature = convert_message(server_sig_str, 'SignedMessage')  # 转换为签名消息

        format_and_print('1.5.Receive blockchain signature and verify success', "-", "center")
        return client_id, server_signature, transfer_time
    except Exception as e:
        format_and_print(f'1.5.Error calling decrypt_and_verify_data():{e}')


# 1.6.验证区块链签名
def verify_server_signature(ecc, server_verify_key, server_sig):
    format_and_print('1.6.Start verifying blockchain signatures', '.')
    try:
        verify_result = ecc.ecc_verify(server_verify_key, server_sig)
        format_and_print('1.6.Blockchain Signature Verification Successful', '-', 'center')
        return verify_result
    except Exception as e:
        format_and_print(f'1.6.Error calling decrypt_and_verify_data():{e}')


# 1.7.保存ecc密钥
def save_gw_ecc_key(client_id, client_public_key, client_private_key, client_verify_key, client_sign_key,
                    server_public_key, server_verify_key):
    format_and_print('1.7.Start saving ecc keys', '.')
    try:
        folder_path = get_folder_path(str(client_id))
        # 判断文件夹是否存在
        if os.path.exists(folder_path):
            format_and_print(f'1.7.Gateway is registered')
        else:
            # 创建文件夹
            os.makedirs(folder_path)
            save_key_to_file(client_public_key, 'pk_gw', folder_path)
            save_key_to_file(client_private_key, 'sk_gw', folder_path)
            save_key_to_file(client_verify_key, 'pk_sig_gw', folder_path)
            save_key_to_file(client_sign_key, 'sk_sig_gw', folder_path)
            save_key_to_file(server_public_key, 'pk_bc', folder_path)
            save_key_to_file(server_verify_key, 'pk_sig_bc', folder_path)
            format_and_print(f'1.7.ECC key saved successfully', '-', 'center')
    except Exception as e:
        format_and_print(f'1.6.Error calling save_ecc_key():{e}')


# 1.网关身份注册流程
def gw_register(client_socket):
    format_and_print('1.Starting the Identity Enrollment Process', ':')
    try:
        # 发送消息类型
        send_with_header(client_socket, b"GATEWAY REGISTRATION")
        # 1.1.生成网关信息
        client_hash_info = gw_info_generate()
        # 1.2.生成网关ecc密钥对
        client_private_key, client_public_key, client_sign_key, client_verify_key, ecc = generate_ecc_key()
        # 1.3.交换公钥
        server_public_key, server_verify_key, tt1, tt2 = bc_pk_exchange(client_socket, client_public_key,
                                                                        client_verify_key)
        # 1.4.发送网关签名和注册信息
        sign_encrypt_and_send(ecc, client_sign_key, client_hash_info, client_private_key, server_public_key,
                              client_socket)
        # 1.5.接收区块链签名
        client_id, server_sig, tt3 = decrypt_and_verify_data(client_socket, ecc, client_private_key, server_public_key)
        # 1.6.验证区块链签名
        verify_result = verify_server_signature(ecc, server_verify_key, server_sig)
        # 1.7.保存ecc密钥
        save_gw_ecc_key(client_id, client_public_key, client_private_key, client_verify_key, client_sign_key,
                        server_public_key, server_verify_key)
        format_and_print('Gateway registration complete', '-*', 'center')
        return client_id, verify_result, tt1, tt2, tt3

    except Exception as e:
        format_and_print(f'1.Error calling gw_register():{e}')
