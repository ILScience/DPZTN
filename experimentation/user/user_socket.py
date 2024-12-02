from zerotrustnetworkelement.user.user_info import *
from zerotrustnetworkelement.user.exchange_key_with_gw import *
import socket
from zerotrustnetworkelement.user.user_configure import *
from zerotrustnetworkelement.function import *


def load_register_key():
    format_and_print('2.1 Loading the required key for registration', '.', 'left')
    try:
        client_public_key = load_key_from_file('pk_user')  # 加载网关公钥
        client_private_key = load_key_from_file("sk_user")  # 加载区块链私钥
        client_verify_key = load_key_from_file('pk_sig_user')  # 加载网关认证密钥
        client_sign_key = load_key_from_file('sk_sig_user')  # 加载区块链签名密钥
        server_public_key = load_key_from_file("pk_gateway")  # 加载区块链公钥
        server_verify_key = load_key_from_file("pk_sig_gateway")  # 加载区块链认证密钥
        format_and_print('2.1 Key loaded successfully', '-', 'center')
        return (client_public_key, client_private_key, client_verify_key,
                client_sign_key, server_public_key, server_verify_key)
    except Exception as e:
        format_and_print(f'2.1 Error calling load_register_key():{e}', chr(0x00D7), 'left')


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
def gw_register(client_socket, ecc, client_hash_info, server_pk_sig):
    format_and_print('2.Starting the Identity Enrollment Process', ':', 'left')
    try:
        # 获取注册过程中使用的公钥
        (client_public_key, client_private_key, client_verify_key, client_sign_key,
         server_public_key, server_verify_key) = load_register_key()

        # 发送消息类型
        send_with_header(client_socket, b"REGISTRATION")
        # 发送网关签名和注册信息
        sign_encrypt_and_send(ecc, client_sign_key, client_hash_info, client_private_key, server_public_key,
                              client_socket)
        # 接收区块链签名
        client_id, server_sig, tt = decrypt_and_verify_data(client_socket, ecc, client_private_key, server_public_key)
        # 验证签名
        result = ecc.ecc_verify(server_pk_sig, server_sig)
        return client_id, result, tt

    except Exception as e:
        format_and_print(f'2.Identity registration failure:{e}', chr(0x00D7), 'left')


def user_main():
    try:
        uinfo = user_info_generate()
        user_sk, user_pk, user_sk_sig, user_pk_sig, ecc = user_key()

        user_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建 socket 对象
        user_socket.bind((user_ip, user_port))  # 绑定ip,port
        user_socket.connect((gateway_ip, gateway_port))  # 连接到区块链服务器
        format_and_print(f"Connected to blockchain server at {gateway_ip}:{gateway_port} from {user_ip}:{user_port}",
                         '.', 'left')
        # 交换公钥
        bc_pk, bc_pk_sig, tt1, tt2, exchange_key_duration = pk_exchange(user_socket, user_pk, user_pk_sig)
        time_dict1 = {'tt1': tt1, 'tt2': tt2, 'exchange_key_duration': exchange_key_duration}

        # 网关注册
        register_start_time = get_timestamp()
        gid, reg_result, tt3 = user_register(user_socket, ecc, user_hash_info, gateway_pk_sig)

    except Exception as e:
        print(e)


if __name__ == '__main__':
    user_main()
