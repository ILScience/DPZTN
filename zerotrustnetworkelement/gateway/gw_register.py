from zerotrustnetworkelement.gateway.exchange_key_with_bc import *
from zerotrustnetworkelement.gateway.gw_info import *


def sign_encrypt_and_send(ecc, client_sign_key, client_hash_info, client_private_key, server_public_key, client_socket):
    format_and_print('2.2 Start generating gateway signatures and send them to the blockchain', '.', 'left')
    try:
        # 生成签名
        client_sig = ecc.ecc_sign(client_sign_key, client_hash_info)

        # 加密消息
        message1 = ecc.ecc_encrypt(client_private_key, server_public_key,
                                   f"{client_hash_info}||{client_sig}")

        # 发送消息
        send_with_header(client_socket, convert_message(message1, 'bytes'))
        format_and_print("2.2 Signed and encrypted message sent successfully", "-", "center")
    except Exception as e:
        # 捕获异常并打印错误信息
        format_and_print(f'2.2 Error calling sign_encrypt_and_send():{e}', chr(0x00D7), 'left')


# 解密数据并验证签名
def decrypt_and_verify_data(client_socket, ecc, client_private_key, server_public_key):
    format_and_print('2.3 Start receiving blockchain signatures and verify', '.', 'left')
    try:
        data, transfer_time = recv_with_header(client_socket)
        message2 = convert_message(data, 'str')  # 接收加密消息
        decrypted_message = ecc.ecc_decrypt(client_private_key, server_public_key, message2)  # 解密消息
        client_id_str, server_sig_str = decrypted_message.split(
            "||")  # 解析消息

        # 转换数据类型
        client_id = convert_message(client_id_str, 'UUID')  # 转换为 UUID
        server_sig = convert_message(server_sig_str, 'SignedMessage')  # 转换为签名消息

        format_and_print('2.3 Receive blockchain signature and verify success', "-", "center")
        return client_id, server_sig, transfer_time
    except Exception as e:
        format_and_print(f'2.3 Error calling decrypt_and_verify_data():{e}', chr(0x00D7), 'left')


# 网关身份注册流程
def gw_register(client_socket):
    format_and_print('2.Starting the Identity Enrollment Process', ':', 'left')
    try:
        # 发送消息类型
        send_with_header(client_socket, b"GATEWAY REGISTRATION")
        # 生成网关信息
        client_hash_info = gw_info_generate()  # 网关身份信息生成
        client_private_key, client_public_key, client_sign_key, client_verify_key, ecc = gw_key()  # 初始化区块链密钥

        # 交换公钥
        server_public_key, server_verify_key, tt1, tt2, exchange_key_duration = bc_pk_exchange(client_socket,
                                                                                               client_public_key,
                                                                                               client_verify_key)
        time_dict1 = {'tt1': tt1, 'tt2': tt2, 'exchange_key_duration': exchange_key_duration}
        # 发送网关签名和注册信息
        sign_encrypt_and_send(ecc, client_sign_key, client_hash_info, client_private_key, server_public_key,
                              client_socket)
        # 接收区块链签名
        client_id, server_sig, tt = decrypt_and_verify_data(client_socket, ecc, client_private_key, server_public_key)
        # 验证签名
        append_to_json(client_id, time_dict1)
        result = ecc.ecc_verify(server_verify_key, server_sig)

        folder_path = get_folder_path(str(client_id))
        # 判断文件夹是否存在
        if os.path.exists(folder_path):
            format_and_print(f'Gateway is registered', chr(0x00D7), 'left')
        else:
            # 创建文件夹
            os.makedirs(folder_path)
            save_key_to_file(client_public_key, 'pk_gw', folder_path)
            save_key_to_file(client_private_key, 'sk_gw', folder_path)
            save_key_to_file(client_verify_key, 'pk_sig_gw', folder_path)
            save_key_to_file(client_sign_key, 'sk_sig_gw', folder_path)
            save_key_to_file(server_public_key, 'pk_bc', folder_path)
            save_key_to_file(server_verify_key, 'pk_sig_bc', folder_path)
            return client_id, result, tt

    except Exception as e:
        format_and_print(f'2.Identity registration failure:{e}', chr(0x00D7), 'left')
