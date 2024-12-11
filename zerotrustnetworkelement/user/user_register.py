from zerotrustnetworkelement.encryption.myhash import *
from zerotrustnetworkelement.encryption.ecc import *
from zerotrustnetworkelement.function import *


# 1.1.获取用户身份属性信息
def user_info_generate():
    format_and_print('1.1.Querying user information', '.')
    try:
        ip, client_info = get_network_info()  # 生成用户属性信息
        user_name = 'ip707'
        user_password = '123456'
        user_info = f'{client_info}||{user_name}||{user_password}'
        user_hash_info = hash_encrypt(user_info)
        format_and_print('1.1.Successful get user information', '-', 'center')
        return user_hash_info
    except Exception as e:
        format_and_print(f'1.1.Error in user_info_generate():{str(e)}')


# 1.2.生成用户ecc密钥
def generate_user_key():
    format_and_print('1.2.Generating user ecc keys', '.')
    try:
        ecc = ECC()
        private_key, public_key = ecc.ecc_genkey()
        signing_key, verify_key = ecc.ecc_genkey_sign()
        format_and_print('1.2.ECC keys generated successful', '-', 'center')
        return private_key, public_key, signing_key, verify_key, ecc
    except Exception as e:
        format_and_print(f'1.2.Error in generate_user_key():{str(e)}')


# 1.3.交换公钥
def pk_exchange(user_socket, user_public_key, user_verify_key):
    format_and_print('1.3.Exchanging Key', ':')
    try:
        data, transfer_time1 = recv_with_header(user_socket)
        server_public_key = convert_message(data, 'PublicKey')  # 接收区块链公钥
        data, transfer_time2 = recv_with_header(user_socket)
        server_verify_key = convert_message(data, 'VerifyKey')  # 接收区块链验证公钥

        send_with_header(user_socket, convert_message(user_public_key, 'bytes'))  # 发送网关公钥
        send_with_header(user_socket, convert_message(user_verify_key, 'bytes'))
        format_and_print('1.3.Key exchange successful', '=', 'center')
        return server_public_key, server_verify_key, transfer_time1, transfer_time2

    except Exception as e:
        format_and_print(f'1.3.Error calling pk_exchange():{e}')


# 1.4.发送用户签名和用户加密消息
def sign_encrypt_and_send(ecc, user_sign_key, user_hash_info, user_private_key, gateway_public_key, user_socket):
    format_and_print('1.4.Start generating user signatures and send them to the gateway', '.', 'left')
    try:
        # 生成签名
        user_sig = ecc.ecc_sign(user_sign_key, convert_message(user_hash_info, 'bytes'))
        # 加密消息
        message1 = ecc.ecc_encrypt(user_private_key, gateway_public_key, f"{user_hash_info}||{user_sig}")
        # 发送消息
        send_with_header(user_socket, convert_message(message1, 'bytes'))
        format_and_print("1.4.Signed and encrypted message sent successfully", "-", "center")
    except Exception as e:
        format_and_print(f'1.4.Error calling sign_encrypt_and_send():{e}')


# 1.5.解密数据并验证网关签名
def decrypt_and_verify_data(user_socket, ecc, user_private_key, gateway_public_key):
    format_and_print('1.5.Start receiving blockchain signatures and verify', '.', 'left')
    try:
        data, transfer_time = recv_with_header(user_socket)
        message2 = convert_message(data, 'str')  # 接收加密消息
        decrypted_message = ecc.ecc_decrypt(user_private_key, gateway_public_key, message2)  # 解密消息
        user_id_str, gateway_sig_str = decrypted_message.split("||")  # 解析消息

        # 转换数据类型
        user_id = convert_message(user_id_str, 'UUID')  # 转换为 UUID
        gateway_sig = convert_message(gateway_sig_str, 'SignedMessage')  # 转换为签名消息

        format_and_print('1.5.Receive blockchain signature and verify success', "-", "center")
        return user_id, gateway_sig, transfer_time
    except Exception as e:
        format_and_print(f'1.5.Error calling decrypt_and_verify_data():{e}')


# 1.6.验证签名
def verify_gateway_signature(ecc, gateway_verify_key, gateway_sig):
    format_and_print('1.6.Start verifying gateway signature', '.')
    try:
        result = ecc.ecc_verify(gateway_verify_key, gateway_sig)
        return result
    except Exception as e:
        format_and_print(f'1.6.Error calling verify_gateway_signature():{e}')


# 1.7.保存用户ecc密钥组
def save_user_keys(user_id, user_public_key, user_private_key, user_verify_key, user_sign_key,
                   gateway_public_key, gateway_verify_key):
    format_and_print('1.7.Saving user ecc keys', '.')
    try:
        user_folder_path = get_folder_path('user' +str(user_id))
        # 判断文件夹是否存在
        if os.path.exists(user_folder_path):
            format_and_print(f'Gateway is registered', chr(0x00D7), 'left')
        else:
            # 创建文件夹
            os.makedirs(user_folder_path)
            save_key_to_file(user_public_key, 'pk_user', user_folder_path)
            save_key_to_file(user_private_key, 'sk_user', user_folder_path)
            save_key_to_file(user_verify_key, 'pk_sig_user', user_folder_path)
            save_key_to_file(user_sign_key, 'sk_sig_user', user_folder_path)
            save_key_to_file(gateway_public_key, 'pk_gateway', user_folder_path)
            save_key_to_file(gateway_verify_key, 'pk_sig_gateway', user_folder_path)
    except Exception as e:
        format_and_print(f'1.7.Error calling save_user_keys():{e}')


# 1.网关身份注册流程
def user_reg(user_socket):
    format_and_print('1.Starting the Identity Enrollment Process', ':', 'left')
    try:
        # 发送消息类型
        send_with_header(user_socket, b"USER REGISTRATION")
        # 1.1.获取用户身份属性信息
        user_hash_info = user_info_generate()
        # 1.2.生成用户ecc密钥
        user_private_key, user_public_key, user_sign_key, user_verify_key, ecc = generate_user_key()
        # 1.3.交换公钥
        gateway_public_key, gateway_verify_key, tt1, tt2 = pk_exchange(user_socket, user_public_key,
                                                                       user_verify_key)

        # 1.4.发送用户签名和用户加密消息
        sign_encrypt_and_send(ecc, user_sign_key, user_hash_info, user_private_key, gateway_public_key,
                              user_socket)
        # 1.5.解密数据并验证网关签名
        user_id, gateway_sig, tt3 = decrypt_and_verify_data(user_socket, ecc, user_private_key, gateway_public_key)
        # 1.6.验证签名
        verify_result = verify_gateway_signature(ecc, gateway_verify_key, gateway_sig)
        if verify_result:
            format_and_print('1.6.Gateway Signature Verification Successful', '-', 'center')
            save_user_keys(user_id, user_public_key, user_private_key, user_verify_key, user_sign_key,
                           gateway_public_key, gateway_verify_key)
            return user_id, verify_result, tt1, tt2, tt3
        else:
            format_and_print('1.6.Gateway Signature Verification Failed')
            return None, None, None, None, None
    except Exception as e:
        format_and_print(f'1.Error calling user_reg():{e}')

