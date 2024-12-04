from zerotrustnetworkelement.function import *
from zerotrustnetworkelement.encryption.ecdh import *
from zerotrustnetworkelement.blockchain.bc_function import *


# 2.1接收用户加密消息和gid，验证gid状态，生成uid
def receive_user_identity(client_socket, server_private_key):
    format_and_print('2.1 Start receiving user encrypted identities and user signatures', '.', 'left')
    try:
        client_public_key = load_key_from_file('pk_gw')  # 加载网关公钥

        aes_key = generate_aes_key(server_private_key, client_public_key)  # 生成aes密钥

        data, transfer_time = recv_with_header(client_socket)
        message2 = convert_message(data, 'str')
        gateway_id, user_hash_info = aes_decrypt(aes_key, message2).split("||")  # 消息解密

        client_hash_info = convert_message(user_hash_info, 'bytes')  # 将用户身份加密消息，由str转换成bytes
        user_id = generate_gid(client_hash_info)

        message3 = aes_encrypt(aes_key, convert_message(user_id, 'bytes'))
        send_with_header(client_socket, message3)

        format_and_print('2.1 User encrypted identity information and user signature received successfully', '-',
                         'center')
        return client_hash_info, user_id, transfer_time
    except Exception as e:
        format_and_print(f'2.1 Error calling receive_user_identity():{e}', chr(0x00D7), 'left')


def user_register(user_socket, blockchain_sk):
    user_hash_info, uid, tt1 = receive_user_identity(user_socket, blockchain_sk)

# 接收到网关gid,查询gid是否注册，获取网关公钥，和验证公钥
# 接收到用户的注册信息，查询用户是否注册
# 用户未注册则生成uid，返回给网关
