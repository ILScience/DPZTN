from zerotrustnetworkelement.function import *
from zerotrustnetworkelement.encryption.ecdh import *
from zerotrustnetworkelement.blockchain.bc_function import *

def receive_user_identity(client_socket, ecc, server_private_key, client_public_key, aes_key):
    format_and_print('2.1 Start receiving user encrypted identities and user signatures', '.', 'left')
    try:
        data, transfer_time = recv_with_header(client_socket)
        message_1 = convert_message(data, 'str')
        gateway_id, user_hash_info = aes_decrypt(aes_key, message_1).split("||")  # 消息解密

        client_hash_info = convert_message(user_hash_info, 'bytes')  # 将用户身份加密消息，由str转换成bytes
        user_id = generate_gid(client_hash_info)

        message_1= aes_encrypt(aes_key,convert_message(user_id,'bytes'))
        send_with_header(client_socket,message_1)

        format_and_print('2.1 User encrypted identity information and user signature received successfully', '-',
                         'center')
        return client_hash_info, transfer_time
    except Exception as e:
        format_and_print(f'2.1 Error calling receive_user_identity():{e}', chr(0x00D7), 'left')


def user_register(user_socket, ecc, gateway_sk, gateway_pk, aes_key):
    receive_user_identity(user_socket, ecc, gateway_sk, gateway_pk, aes_key)


# 接收到网关gid,查询gid是否注册，获取网关公钥，和验证公钥
# 接收到用户的注册信息，查询用户是否注册
# 用户未注册则生成uid，返回给网关
