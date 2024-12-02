from zerotrustnetworkelement.function import *
from zerotrustnetworkelement.encryption.ecc import *
from zerotrustnetworkelement.gateway.gw_function import *
from zerotrustnetworkelement.encryption.myhash import *
import socket
from zerotrustnetworkelement.gateway.gw_configure import *
from zerotrustnetworkelement.gateway.figure import *
from zerotrustnetworkelement.encryption.ecdh import *
from zerotrustnetworkelement.encryption.zkp import *


def gw_key():
    ecc = ECC()
    if os.path.exists("sk_gw.key") and os.path.exists("pk_gw.key"):
        private_key = load_key_from_file("sk_gw")
        public_key = load_key_from_file('pk_gw')
    else:
        private_key, public_key = ecc.ecc_genkey()
        save_key_to_file(private_key, "sk_gw")
        save_key_to_file(public_key, 'pk_gw')

    if os.path.exists("sk_sig_gw.key") and os.path.exists("pk_sig_gw.key"):
        signing_key = load_key_from_file("sk_sig_gw")
        verify_key = load_key_from_file('pk_sig_gw')
    else:
        signing_key, verify_key = ecc.ecc_genkey_sign()
        save_key_to_file(signing_key, "sk_sig_gw")
        save_key_to_file(verify_key, 'pk_sig_gw')
    return private_key, public_key, signing_key, verify_key, ecc


def gw_info_generate():
    ip, client_info = get_network_info()  # 生成网关信息gw_Info
    client_hash_info = hash_encrypt(convert_message(client_info, 'str'))  # 对网关身份信息进行加密
    return client_info, client_hash_info


# 与区块链建立连接并交换公钥
def pk_exchange(client_socket, client_public_key, client_verify_key):
    try:
        # 接收区块链公钥
        server_public_key = convert_message(recv_with_header(client_socket), 'PublicKey')  # 接收区块链公钥
        server_verify_key = convert_message(recv_with_header(client_socket), 'VerifyKey')  # 接收区块链验证公钥
        save_key_to_file(server_public_key, 'pk_bc')
        save_key_to_file(server_verify_key, 'pk_sig_bc')
        # 发送网关公钥
        send_with_header(client_socket, convert_message(client_public_key, 'bytes'))
        send_with_header(client_socket, convert_message(client_verify_key, 'bytes'))
        return server_public_key, server_verify_key
    except ConnectionError as conn_err:
        format_and_print(f"Connection error during key exchange: {conn_err}", chr(0x00D7), 'left')
    except ValueError as val_err:
        format_and_print(f"Value error during key exchange: {val_err}", chr(0x00D7), 'left')
    except IOError as io_err:
        format_and_print(f"File I/O error during key exchange: {io_err}", chr(0x00D7), 'left')
    except Exception as e:
        format_and_print(f"An unexpected error occurred during key exchange: {e}", chr(0x00D7), 'left')


def load_key():
    client_public_key = load_key_from_file('pk_gw')  # 加载网关公钥
    client_private_key = load_key_from_file("sk_gw")  # 加载区块链私钥
    client_verify_key = load_key_from_file('pk_sig_gw')  # 加载网关认证密钥
    client_sign_key = load_key_from_file('sk_sig_gw')  # 加载区块链签名密钥
    server_public_key = load_key_from_file("sk_pk")  # 加载区块链公钥
    server_verify_key = load_key_from_file("pk_sig_bc")  # 加载区块链认证密钥
    return client_public_key, client_private_key, client_verify_key, client_sign_key, server_public_key, server_verify_key


def sign_encrypt_and_send(ecc, client_sign_key, client_hash_info, client_private_key, server_public_key, client_socket):
    try:
        # 生成签名
        client_sig = ecc.ecc_sign(client_sign_key, client_hash_info)

        # 加密消息
        message1 = ecc.ecc_encrypt(client_private_key, server_public_key,
                                   f"{client_hash_info}||{client_sig}||{get_timestamp()}")

        # 发送消息
        send_with_header(client_socket, convert_message(message1, 'bytes'))
        format_and_print("Signed and encrypted message sent successfully", "-", "center")
    except Exception as e:
        # 捕获异常并打印错误信息
        format_and_print(f"Error occurred during signing, encrypting, or sending: {e}", chr(0x00D7), "left")


# 解密数据并验证签名
def decrypt_and_verify_data(client_socket, ecc, client_private_key, server_public_key):
    try:
        message2 = convert_message(recv_with_header(client_socket), 'str')  # 接收加密消息
        decrypted_message = ecc.ecc_decrypt(client_private_key, server_public_key, message2)  # 解密消息
        client_id_str, server_sig_str, registration_start_time_str, timestamp_str = decrypted_message.split(
            "||")  # 解析消息

        # 转换数据类型
        client_id = convert_message(client_id_str, 'UUID')  # 转换为 UUID
        server_sig = convert_message(server_sig_str, 'SignedMessage')  # 转换为签名消息
        registration_start_time = convert_message(registration_start_time_str, 'int')  # 转换为 int
        registration_end_time = convert_message(timestamp_str, 'int')  # 转换为 int

        # 计算注册时长
        registration_duration = registration_end_time - registration_start_time
        return client_id, server_sig, registration_duration
    except Exception as e:
        # 捕获任何错误并返回清晰的错误信息
        raise RuntimeError(f"Failed to decrypt or verify data: {e}")


# 网关身份注册流程
def gw_register(client_socket, ecc, client_hash_info, server_pk_sig):
    # 获取注册过程中使用的公钥
    client_public_key, client_private_key, client_verify_key, client_sign_key, server_public_key, server_verify_key = load_key()

    # 发送消息类型
    print("Send Request Type!")
    send_with_header(client_socket, (f"REGISTRATION", 'bytes'))
    # 发送网关签名和注册信息
    sign_encrypt_and_send(ecc, client_sign_key, client_hash_info, client_private_key, server_public_key, client_socket)
    # 接收区块链签名
    client_id, server_sig, registration_duration = decrypt_and_verify_data(client_socket, ecc, client_private_key,
                                                                           server_public_key)
    # 验证签名
    result = ecc.ecc_verify(server_pk_sig, server_sig)
    print('=' * 150)
    return client_id, result


def gw_auth(client_socket, client_id):
    # 获取认证过程中使用的公钥
    client_public_key, client_private_key, client_verify_key, client_sign_key, server_public_key, server_verify_key = load_key()

    # 发送消息类型
    print('Send Message Type')
    send_with_header(client_socket, convert_message(f"AUTHENTICATION", 'bytes'))
    send_with_header(client_socket, convert_message(f"{client_id}", 'bytes'))  # 发送gid

    # 生成会话密钥
    aes_key = generate_aes_key(client_private_key, server_public_key)

    # 获取网关身份信息
    client_info1 = get_network_info()  # 生成网关信息 gw_Info
    client_hash_info1 = hash_encrypt(convert_message(client_info1, 'str'))  # 对网关身份信息进行加密

    # 零知识认证
    # 确定零知识认证曲线
    client_zk = ZK.new(curve_name="secp256k1", hash_alg="sha3_256")
    # 构建网关签名并发送给区块链
    client_sig = client_zk.create_signature(client_hash_info1)
    print(type(client_sig))
    message1 = aes_encrypt(aes_key, convert_message(client_sig, 'bytes'))
    send_with_header(client_socket, message1)

    # 接收服务器发送的 token
    print('Receive tokens from the server!')
    token_encrypt = client_socket.recv(1024).decode()
    token = aes_decrypt(aes_key, token_encrypt)

    # 使用 token 创建证明并发送给服务器
    print('Use the token to create the proof and send it to the server')
    proof = client_zk.sign(client_hash_info1, token).dump()
    proof_encrypt = aes_encrypt(aes_key, proof)
    client_socket.sendall(proof_encrypt.encode())

    # 接收服务器的验证结果
    print('Receive validation results from the server')
    result = aes_decrypt(aes_key, client_socket.recv(1024).decode())
    print("Gateway auth successful!" if result == "AUTH_SUCCESS" else "Failure!")
    print('*' * 150)


def gateway_main():
    # 生成网关信息
    gw_sk, gw_pk, gw_sk_sig, gw_pk_sig, ecc = gw_key()  # 初始化区块链密钥
    gw_info, gw_hash_info = gw_info_generate()  # 网关身份信息生成

    # 与区块链连接
    gw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建 socket 对象
    gw_socket.bind((gw_ip, gw_port))  # 绑定ip,port
    gw_socket.connect((bc_ip, bc_port))  # 连接到区块链服务器
    format_and_print(f"Connected to blockchain server at {bc_ip}:{bc_port} from {gw_ip}:{gw_port}", '.', 'left')

    # 交换公钥
    print(exchanging_publickey)
    bc_pk, bc_pk_sig = pk_exchange(gw_socket, gw_pk, gw_pk_sig)
    print(exchange_completed)
    # 网关注册
    print(gateway_registering)
    gid, reg_result = gw_register(gw_socket, ecc, gw_hash_info, bc_pk_sig)
    print(gateway_registration_completed)
    # 网关认证
    print(gateway_authentication)
    gw_auth(gw_socket, gid)
    print(gateway_authentication_completed)


if __name__ == '__main__':
    gateway_main()
