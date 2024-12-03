from zerotrustnetworkelement.function import *
from zerotrustnetworkelement.encryption.ecdh import *


# 2.1 加载密钥（用户公钥、用户验证密钥，网关公钥、网关私钥、网关签名公钥、网关认证密钥）
def load_register_key():
    format_and_print('2.1 Loading the required key for user registration', '.', 'left')
    try:
        server_public_key = load_key_from_file("pk_gateway")  # 加载网关公钥
        server_private_key = load_key_from_file("sk_gateway")  # 加载网关私钥
        server_verify_key = load_key_from_file("pk_sig_gateway")  # 加载网关认证密钥
        server_sign_key = load_key_from_file('sk_sig_gateway')  # 加载网关签名密钥
        client_public_key = load_key_from_file('pk_user')  # 加载用户公钥
        client_verify_key = load_key_from_file('pk_sig_user')  # 加载用户认证密钥
        format_and_print('2.1 Key loaded successfully', '-', 'center')
        return (server_public_key, server_private_key, server_verify_key,
                server_sign_key, client_public_key, client_verify_key)
    except Exception as e:
        format_and_print(f'2.1 Error calling load_register_key():{e}', chr(0x00D7), 'left')


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
    except Exception as e:
        format_and_print(f'2.2 Error calling receive_user_info():{e}', chr(0x00D7), 'left')


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
def send_gid_and_uinfo(client_socket, client_hash_info, aes_key_to_bc, gid):
    format_and_print(f'Send gid and user identity information to the blockchain', '.', 'left')
    try:
        message2 = aes_encrypt(aes_key_to_bc, convert_message(f'{gid}||{client_hash_info}', 'bytes'))
        send_with_header(client_socket, message2)
        format_and_print('2.4 Gid and user encrypted message sent.', '-', 'center')
    except Exception as e:
        format_and_print(f'2.4 Error calling send_gid_and_uinfo():{e}', chr(0x00D7), 'left')


# 2.5 接收并解析出uid
def recv_uid_from_bc(server_socket, aes_key_to_bc):
    format_and_print(f'2.5 Send gid and user identity information to the blockchain', '.', 'left')
    try:
        data, transfer_time = recv_with_header(server_socket)
        user_id = convert_message(aes_decrypt(aes_key_to_bc, data), 'UUID')
        format_and_print('2.5 Receive and parse out the uid.', '-', 'center')
        return user_id, transfer_time
    except Exception as e:
        format_and_print(f'2.5 Error calling recv_uid_from_bc():{e}', chr(0x00D7), 'left')


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
def user_register(user_socket, ecc, aes_key, gid, gateway_socket):
    format_and_print(f'2 Start the user registration process.', '.', 'left')
    try:
        gateway_pk, gateway_sk, gateway_sig_pk, gateway_sig_sk, user_pk, user_sig_pk = load_register_key()
        client_hash_info, client_sig, tt_u = receive_user_info(user_socket, ecc, gateway_sk, user_pk)
        verify_result = verify_user_sign(ecc, user_sig_pk, client_sig)
        if verify_result:
            send_gid_and_uinfo(user_socket, client_hash_info, aes_key, gid)
            user_id, tt_b = recv_uid_from_bc(gateway_socket, aes_key)
            generate_gateway_sign(ecc, gateway_sig_sk, user_id, gateway_sk, user_pk, user_socket)
            return tt_u, tt_b
        else:
            format_and_print(f'2.3 User Signature Verification Failure!', chr(0x00D7), 'left')
    except Exception as e:
        format_and_print(f'2 Error calling user_register():{e}', chr(0x00D7), 'left')
