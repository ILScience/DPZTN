from zerotrustnetworkelement.encryption.ecdh import *
from zerotrustnetworkelement.encryption.ecc import *
from zerotrustnetworkelement.function import *


# 3.1.生成网关密钥对，用于与用户进行加密通信
def generate_gateway_ecc_key():
    format_and_print('3.1.The ecc key pair being generated', ':')
    try:
        ecc = ECC()
        gateway_private_key, gateway_public_key = ecc.ecc_genkey()
        gateway_signing_key, gateway_verify_key = ecc.ecc_genkey_sign()
        format_and_print('3.1.The ecc key pair was successfully generated', '-', 'center')
        return gateway_private_key, gateway_public_key, gateway_signing_key, gateway_verify_key, ecc
    except ValueError as v:
        format_and_print(f"3.1.ValueError in generate_ecc_key(): {str(v)}")
    except TypeError as t:
        format_and_print(f"3.1.TypeError in generate_ecc_key(): {str(t)}")
    except Exception as e:
        format_and_print(f"3.1.Unexpected error occurred in generate_ecc_key(): {str(e)}")


# 3.2.公钥交换
def user_pk_exchange(user_socket, gateway_public_key, gateway_verify_key):
    format_and_print('3.2.Exchanging Key', ':')
    try:
        send_with_header(user_socket, convert_message(gateway_public_key, 'bytes'))  # 发送区块链公钥
        send_with_header(user_socket, convert_message(gateway_verify_key, 'bytes'))  # 发送区块链认证密钥

        data, tt_u1 = recv_with_header(user_socket)
        user_public_key = convert_message(data, 'PublicKey')  # 接收用户公钥
        data, tt_u2 = recv_with_header(user_socket)
        user_verify_key = convert_message(data, 'VerifyKey')  # 接收用户认证密钥

        format_and_print('3.2.Key exchange successful', '=', 'center')
        return user_public_key, user_verify_key, tt_u1, tt_u2
    except Exception as e:
        format_and_print(f"3.2.Unexpected error occurred in user_pk_exchange(): {str(e)}")


# 3.3.加载网关与区块链通信密钥
def load_session_key(gw_id):
    format_and_print("3.3.Loading the gateway's communication key with the blockchain", '.')
    try:
        gw_folder_path = get_folder_path('gateway'+str(gw_id))
        sk_gw = load_key_from_file('sk_gw', gw_folder_path)
        pk_bc = load_key_from_file('pk_bc', gw_folder_path)
        aes_key = generate_aes_key(sk_gw, pk_bc)
        format_and_print('3.3.Communication key successfully loaded', '-', 'center')
        return aes_key
    except Exception as e:
        format_and_print(f"3.3.Unexpected error occurred in load_gw_key(): {str(e)}")


# 3.4.接收用户加密身份信息和用户签名
def receive_user_info(user_socket, ecc, gateway_private_key, user_public_key):
    format_and_print('3.4.Start receiving user encrypted identities and user signatures', '.')
    try:
        data, transfer_time = recv_with_header(user_socket)
        message1 = convert_message(data, 'str')
        user_hash_info, user_sig_str = ecc.ecc_decrypt(gateway_private_key, user_public_key,
                                                       message1).split("||")  # 消息解密
        user_hash_info = convert_message(user_hash_info, 'bytes')  # 将用户身份加密消息，由str转换成bytes
        user_sig = convert_message(user_sig_str, 'SignedMessage')  # 将用户签名由str转换成SignedMessage
        format_and_print('3.4.Successful receipt of user information and user signature', '-', 'center')
        return user_hash_info, user_sig, transfer_time
    except Exception as e:
        format_and_print(f"3.4.Unexpected error occurred in receive_user_info(): {str(e)}")


# 3.5.验证用户签名
def verify_user_signature(ecc, user_verify_key, user_sig):
    format_and_print('3.5.Start verifying user signatures', '.')
    try:
        verify_result = ecc.ecc_verify(ecc, user_verify_key, user_sig)
        return verify_result
    except Exception as e:
        format_and_print(f"3.5.Unexpected error occurred in verify_user_signature(): {str(e)}")


# 3.6.将gid和用户加密信息发送给区块链
def send_gid_and_user_info(gw_socket, user_hash_info, aes_key_to_bc, gw_id):
    format_and_print(f'3.6.Send gid and user identity information to the blockchain', '.')
    try:
        send_with_header(gw_socket, b"USER REGISTRATION")  # 发送消息类型
        send_with_header(gw_socket, convert_message(f'{gw_id}', 'bytes'))
        message2 = aes_encrypt(aes_key_to_bc, convert_message(f'{user_hash_info}', 'bytes'))
        send_with_header(gw_socket, message2)
        format_and_print('3.6.Gid and user encrypted message sent.', '-', 'center')
    except Exception as e:
        format_and_print(f"3.6.Unexpected error occurred in send_gid_and_user_info(): {str(e)}")


# 3.7.接收并解析出uid
def recv_uid_from_bc(gw_socket, aes_key_to_bc):
    format_and_print(f'3.7.Send gid and user identity information to the blockchain', '.')
    try:
        data, transfer_time = recv_with_header(gw_socket)
        user_id = convert_message(convert_message(aes_decrypt(aes_key_to_bc, data), 'str'), 'UUID')
        format_and_print('3.7.Receive and parse out the uid.', '-', 'center')
        return user_id, transfer_time
    except Exception as e:
        format_and_print(f"3.7.Unexpected error occurred in recv_uid_from_bc(): {str(e)}")


# 3.8.保存与用户通信的密钥
def save_gateway_ecc_key(user_id, gateway_public_key, gateway_private_key, gateway_verify_key, gateway_sign_key,
                         user_pk, user_sig_pk):
    format_and_print('3.8.Start storing keys', '.')
    try:
        user_folder_path = get_folder_path('user'+str(user_id))
        if os.path.exists(user_folder_path):
            format_and_print(f'3.8.Gateway is registered')
        else:
            # 创建文件夹
            os.makedirs(user_folder_path)
            save_key_to_file(gateway_public_key, 'pk_gateway', user_folder_path)
            save_key_to_file(gateway_private_key, 'sk_gateway', user_folder_path)
            save_key_to_file(gateway_verify_key, 'pk_sig_gateway', user_folder_path)
            save_key_to_file(gateway_sign_key, 'sk_sig_gateway', user_folder_path)
            save_key_to_file(user_pk, 'pk_user', user_folder_path)
            save_key_to_file(user_sig_pk, 'pk_sig_user', user_folder_path)
            format_and_print('3.8.The key is saved.', "-", "center")
    except Exception as e:
        format_and_print(f'3.8.Unexpected error in save_ecc_key():{str(e)}')


# 3.9.生成网关签名,发送给用户
def generate_gateway_sign(ecc, user_id, user_socket, gateway_sign_key, gateway_private_key, user_public_key):
    format_and_print(f'3.9.Gateway signature being generated.', '.')
    try:
        gateway_signature = ecc.ecc_sign(gateway_sign_key, user_id.bytes)
        message2 = ecc.ecc_encrypt(gateway_private_key, user_public_key, f"{user_id}||{gateway_signature}")
        send_with_header(user_socket, convert_message(message2, 'bytes'))
        format_and_print('3.9.Receive and parse out the uid.', '-', 'center')
    except Exception as e:
        format_and_print(f'3.9.Error calling generate_gateway_sign():{e}')


# 3.用户注册流程
def user_register(gw_socket, user_socket, gw_id):
    format_and_print(f'3.Start the user registration process.', ':')
    try:
        # 3.1.生成ecc密钥对
        gateway_private_key, gateway_public_key, gateway_sign_key, gateway_verify_key, ecc = generate_gateway_ecc_key()
        # 3.2.交换密钥
        user_pk, user_sig_pk, tt_u1, tt_u2 = user_pk_exchange(user_socket, gateway_public_key, gateway_verify_key)
        # 3.3.加载网关与区块链通信密钥
        aes_key_to_bc = load_session_key(gw_id)
        # 3.4.接收用户加密身份信息和用户签名
        client_hash_info, client_sig, tt_u3 = receive_user_info(user_socket, ecc, gateway_private_key, user_pk)
        # 3.5.验证用户签名
        verify_result = verify_user_signature(ecc, user_sig_pk, client_sig)
        if verify_result:
            format_and_print('3.5.User Signature Verification Successful', '-', 'center')
            # 3.6.将gid和用户加密信息发送给区块链
            send_gid_and_user_info(gw_socket, client_hash_info, aes_key_to_bc, gw_id)
            # 3.7.接收并解析出uid
            user_id, tt_b1 = recv_uid_from_bc(gw_socket, aes_key_to_bc)
            # 3.8.保存与用户通信的密钥
            save_gateway_ecc_key(user_id, gateway_public_key, gateway_private_key, gateway_verify_key, gateway_sign_key,
                                 user_pk, user_sig_pk)
            # 3.9.生成网关签名,发送给用户
            generate_gateway_sign(ecc, gateway_sign_key, user_id, gateway_private_key, user_pk, user_socket)
            format_and_print('3.Identity Registration Successful', "=", "center")
            return user_id, tt_u1, tt_u2, tt_u3, tt_b1
        else:
            format_and_print(f'3.5.User Signature Verification Failure!')

    except Exception as e:
        format_and_print(f'3.Error calling user_register():{e}')
