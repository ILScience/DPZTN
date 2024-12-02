from zerotrustnetworkelement.function import *
from zerotrustnetworkelement.encryption.ecdh import *
from noknow.core import ZK
from zerotrustnetworkelement.gateway.gw_function import *
from zerotrustnetworkelement.encryption.myhash import *


def load_auth_key():
    format_and_print('3.1 Loading the required key for auth', '.', 'left')
    try:
        client_private_key = load_key_from_file("sk_gw")  # 加载区块链私钥
        server_public_key = load_key_from_file("pk_bc")  # 加载区块链公钥
        format_and_print('3.1 Key loaded successfully', '-', 'center')
        return client_private_key, server_public_key
    except Exception as e:
        format_and_print(f'3.1 Error calling load_auth_key():{e}', chr(0x00D7), 'left')


# 3.2发送网关签名
def send_gw_sign(client_hash_info1, aes_key, client_socket):
    format_and_print('3.2 Start sending gateway signatures', '.', 'left')
    try:
        # 确定零知识认证曲线
        client_zk = ZK.new(curve_name="secp256k1", hash_alg="sha3_256")
        # 构建网关签名并发送给区块链
        client_sig = client_zk.create_signature(client_hash_info1)
        message1 = aes_encrypt(aes_key, convert_message(client_sig, 'bytes'))
        send_with_header(client_socket, message1)
        format_and_print('3.2 Gateway signature sent successfully', "_", "center")
        return client_zk
    except Exception as e:
        format_and_print(f'3.2 Error calling send_gw_sign():{e}', chr(0x00D7), 'left')


# 3.3 接收服务器发送的 token
def recv_bc_token(client_socket, aes_key):
    format_and_print('3.3 Start receiving tokens from the blockchain', '.', 'left')
    try:
        token_encrypt, transfer_time = recv_with_header(client_socket)
        token_decrypt = aes_decrypt(aes_key, token_encrypt)
        token = convert_message(token_decrypt, 'str')
        format_and_print('3.3 Successfully receive the token sent by the blockchain', "_", "center")
        return token, transfer_time
    except Exception as e:
        format_and_print(f'3.3 Error calling recv_bc_token():{e}', chr(0x00D7), 'left')


# 3.4 生成proof并发送给区块链
def generate_proof_send(client_zk, client_hash_info1, token, aes_key, client_socket):
    format_and_print('3.4 Start Proof Generation', '.', 'left')
    try:
        proof = client_zk.sign(client_hash_info1, token).dump()
        proof_encrypt = aes_encrypt(aes_key, convert_message(proof, 'bytes'))
        send_with_header(client_socket, proof_encrypt)
        format_and_print('3.4 Successfully generated proof', "_", "center")
    except Exception as e:
        format_and_print(f'3.4 Error calling generate_proof_send():{e}', chr(0x00D7), 'left')


# 接收服务器的验证结果
def recv_auth_result(aes_key, client_socket):
    format_and_print('3.5 Start receiving authentication results', '.', 'left')
    try:
        a, transfer_time = recv_with_header(client_socket)
        result = aes_decrypt(aes_key, a)
        if result == b"AUTH_SUCCESS":
            auth_result = True
        else:
            auth_result = False
        format_and_print('3.5 Authentication result received successfully', "_", "center")
        return auth_result, transfer_time
    except Exception as e:
        format_and_print(f'3.5 Error calling recv_auth_result():{e}', chr(0x00D7), 'left')


def gw_auth(client_socket, client_id):
    format_and_print('3.Starting the authentication process', ':', 'left')
    try:
        # 获取认证过程中使用的公钥
        client_private_key, server_public_key = load_auth_key()
        send_with_header(client_socket, b"AUTHENTICATION")  # 发送消息类型
        send_with_header(client_socket, convert_message(f"{client_id}", 'bytes'))  # 发送gid
        aes_key = generate_aes_key(client_private_key, server_public_key)  # 生成会话密钥
        ip1, client_info1 = get_network_info()  # 获取网关身份信息
        client_hash_info1 = hash_encrypt(convert_message(client_info1, 'str'))  # 对网关身份信息进行加密

        # 零知识认证
        # 3.2 发送网关签名
        client_zk = send_gw_sign(client_hash_info1, aes_key, client_socket)
        # 3.3 接收服务器发送的 token
        token, tt1 = recv_bc_token(client_socket, aes_key)

        # 3.4 使用 token 创建证明并发送给服务器
        generate_proof_send(client_zk, client_hash_info1, token, aes_key, client_socket)
        # 3.5 接收服务器的验证结果
        auth_result, tt2 = recv_auth_result(aes_key, client_socket)
        return auth_result, tt1, tt2

    except Exception as e:
        format_and_print(f'3.Authentication failure:{e}', chr(0x00D7), 'left')
