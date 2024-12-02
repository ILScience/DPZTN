from zerotrustnetworkelement.function import *
from zerotrustnetworkelement.encryption.ecdh import *


# 加载密钥（用户公钥、用户验证密钥，网关公钥、网关私钥、网关签名公钥、网关认证密钥）
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


# 接收用户加密身份信息和用户签名,并和gid转发给区块链
def receive_user_identity(client_socket, ecc, server_private_key, client_public_key, aes_key_to_bc, gid):
    format_and_print('2.2 Start receiving user encrypted identities and user signatures', '.', 'left')
    try:
        data, transfer_time = recv_with_header(client_socket)
        message1 = convert_message(data, 'str')
        client_hash_info, client_sig_str = ecc.ecc_decrypt(server_private_key, client_public_key,
                                                           message1).split("||")  # 消息解密
        client_hash_info = convert_message(client_hash_info, 'bytes')  # 将用户身份加密消息，由str转换成bytes

        # 将gid和用户加密信息发送给区块链
        message_1 = aes_encrypt(aes_key_to_bc, convert_message(f'{gid}||{client_hash_info}', 'bytes'))
        send_with_header(client_socket, message_1)

        client_sig = convert_message(client_sig_str, 'SignedMessage')  # 将用户签名由str转换成SignedMessage

        format_and_print('2.2 User encrypted identity information and user signature received successfully', '-',
                         'center')
        return client_hash_info, client_sig, transfer_time
    except Exception as e:
        format_and_print(f'2.2 Error calling receive_user_identity():{e}', chr(0x00D7), 'left')


def user_register(user_socket, ecc, aes_key, gid):
    gateway_pk, gateway_sk, gateway_sig_pk, gateway_sig_sk, user_pk, user_sig_pk = load_register_key()
    client_hash_info, client_sig, transfer_time = receive_user_identity(user_socket, ecc, gateway_sk,
                                                                        gateway_pk, aes_key, gid)

# 接收用户发送的签名和身份信息的加密
# 解密后使用aes加密，添加gid后的消息发送给区块链

# 网关生成网关签名
# 网关接收到区块链生成的uid解密后，加密和网管签名一起发送给用户
