from zerotrustnetworkelement.function import *
from zerotrustnetworkelement.encryption.ecdh import *
from noknow.core import ZK
from zerotrustnetworkelement.gateway.gw_function import *
from zerotrustnetworkelement.encryption.myhash import *


# 2.1.加载网关认证所需要密钥
def load_auth_key(client_id):
    format_and_print('2.1.Loading the required key for auth', '.')
    try:
        folder_path = get_folder_path('gateway'+str(client_id))
        client_private_key = load_key_from_file("sk_gw", folder_path)  # 加载网关私钥
        server_public_key = load_key_from_file("pk_bc", folder_path)  # 加载区块链公钥
        aes_key = generate_aes_key(client_private_key, server_public_key)  # 生成会话密钥
        format_and_print('2.1.Key loaded successfully', '-', 'center')
        return folder_path, client_private_key, server_public_key, aes_key
    except Exception as e:
        format_and_print(f'2.1.Error calling load_auth_key():{e}')


# 2.2.获取新的网关身份信息
def get_new_gw_info():
    format_and_print('2.2.Retrieve gateway identity information', '.')
    try:
        ip, client_info = get_network_info()  # 获取网关身份信息
        client_hash_info = hash_encrypt(convert_message(client_info, 'str'))  # 对网关身份信息进行加密
        format_and_print('2.2.Gateway identity information obtained successfully', '-', 'center')
        return client_hash_info
    except Exception as e:
        format_and_print(f'2.2.Error calling get_new_gw_info():{e}')


# 2.3.发送网关签名
def send_gw_sign(client_hash_info_new, aes_key, client_socket):
    format_and_print('2.3.Start sending gateway signatures', '.')
    try:
        # 确定零知识认证曲线
        client_zk = ZK.new(curve_name="secp256k1", hash_alg="sha3_256")
        # 构建网关签名并发送给区块链
        client_sig = client_zk.create_signature(client_hash_info_new)
        message1 = aes_encrypt(aes_key, convert_message(client_sig, 'bytes'))
        send_with_header(client_socket, message1)
        format_and_print('2.3. Gateway signature sent successfully', "_", "center")
        return client_zk
    except Exception as e:
        format_and_print(f'2.3.Error calling send_gw_sign():{e}')


# 2.4.接收服务器发送的 token
def recv_bc_token(client_socket, aes_key):
    format_and_print('2.4.Start receiving tokens from the blockchain', '.')
    try:
        token_encrypt, transfer_time = recv_with_header(client_socket)
        token_decrypt = aes_decrypt(aes_key, token_encrypt)
        token = convert_message(token_decrypt, 'str')
        format_and_print('2.4.Successfully receive the token sent by the blockchain', "_", "center")
        return token, transfer_time
    except Exception as e:
        format_and_print(f'2.4.Error calling recv_bc_token():{e}')


# 2.5.生成proof并发送给区块链
def generate_proof_send(client_zk, client_hash_info1, token, aes_key, client_socket):
    format_and_print('3.4 Start Proof Generation', '.')
    try:
        proof = client_zk.sign(client_hash_info1, token).dump()
        proof_encrypt = aes_encrypt(aes_key, convert_message(proof, 'bytes'))
        send_with_header(client_socket, proof_encrypt)
        format_and_print('3.4 Successfully generated proof', "_", "center")
    except Exception as e:
        format_and_print(f'3.4 Error calling generate_proof_send():{e}')


# 2.6.接收服务器的验证结果
def recv_auth_result(aes_key, client_socket):
    format_and_print('2.6.Start receiving authentication results', '.')
    try:
        data, transfer_time = recv_with_header(client_socket)
        result = aes_decrypt(aes_key, data)
        if result == b"AUTH_SUCCESS":
            auth_result = True
        else:
            auth_result = False
        format_and_print('2.6.Authentication result received successfully', "_", "center")
        return auth_result, transfer_time
    except Exception as e:
        format_and_print(f'2.6.Error calling recv_auth_result():{e}')

# 2.网关认证
def gw_auth(client_socket, client_id):
    format_and_print('2.Starting the authentication process', ':')
    try:
        send_with_header(client_socket, b"GATEWAY AUTHENTICATION")  # 发送消息类型
        send_with_header(client_socket, convert_message(f"{client_id}", 'bytes'))  # 发送gid
        # 2.1获取认证过程中使用的公钥
        folder_path, client_private_key, server_public_key, aes_key = load_auth_key(client_id)

        # 零知识认证
        # 2.2.获取新的网关身份信息
        client_hash_info_new = get_new_gw_info()
        # 2.3.发送网关签名
        client_zk = send_gw_sign(client_hash_info_new, aes_key, client_socket)
        # 2.4.接收服务器发送的 token
        token, tt1 = recv_bc_token(client_socket, aes_key)
        # 2.5.使用 token 创建证明并发送给服务器
        generate_proof_send(client_zk, client_hash_info_new, token, aes_key, client_socket)
        # 2.6.接收服务器的验证结果
        auth_result, tt2 = recv_auth_result(aes_key, client_socket)
        return auth_result, tt1, tt2

    except Exception as e:
        format_and_print(f'2.Authentication failure:{e}')
