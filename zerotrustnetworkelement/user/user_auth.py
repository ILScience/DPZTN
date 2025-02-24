from zerotrustnetworkelement.encryption.ecdh import *
from noknow.core import ZK
from zerotrustnetworkelement.encryption.myhash import *
from zerotrustnetworkelement.function import *


# 2.1.加载密钥
def load_auth_key(user_id):
    format_and_print('2.1.Loading the required key for auth', '.')
    try:
        user_folder_path = get_folder_path('user' +str(user_id))
        user_private_key = load_key_from_file("sk_user", user_folder_path)  # 加载用户私钥
        gateway_public_key = load_key_from_file("pk_gateway", user_folder_path)  # 加载网关公钥
        aes_key_to_gateway = generate_aes_key(user_private_key, gateway_public_key)  # 生成会话密钥
        format_and_print('2.1.Key loaded successfully', '-', 'center')
        return aes_key_to_gateway
    except Exception as e:
        format_and_print(f'2.1.Error in load_auth_key():{str(e)}')


# 2.2.输入新的用户身份属性信息
def user_info_generate():
    format_and_print('2.2.Querying user information', '.')
    try:
        ip, client_info = get_network_info()  # 生成用户属性信息
        user_name = 'ip707'
        user_password = '123456'
        user_info = f'{client_info}||{user_name}||{user_password}'
        user_hash_info = hash_encrypt(user_info)
        format_and_print('2.2.Successful get user information', '-', 'center')
        return user_hash_info
    except Exception as e:
        format_and_print(f'2.2.Error in user_info_generate():{str(e)}')


# 2.3.发送用户签名
def send_user_sign(user_hash_info_new, aes_key_to_gateway, user_socket):
    format_and_print('2.3.Start sending gateway signatures', '.')
    try:
        # 确定零知识认证曲线
        user_zk = ZK.new(curve_name="secp256k1", hash_alg="sha3_256")
        # 构建用户签名并发送给网关
        user_sig = user_zk.create_signature(user_hash_info_new)
        message1 = aes_encrypt(aes_key_to_gateway, convert_message(user_sig, 'bytes'))
        send_with_header(user_socket, message1)
        format_and_print('2.3.Gateway signature sent successfully', "_", "center")
        return user_zk
    except Exception as e:
        format_and_print(f'2.3.Error calling send_user_sign():{e}')


# 2.4.接收区块链发送的 token
def recv_bc_token(user_socket, aes_key_to_gateway):
    format_and_print('2.4.Start receiving tokens from the gateway', '.')
    try:
        token_encrypt, transfer_time = recv_with_header(user_socket)
        token_decrypt = aes_decrypt(aes_key_to_gateway, token_encrypt)
        token = convert_message(token_decrypt, 'str')
        format_and_print('2.4.Successfully receive the token sent by the blockchain', "_", "center")
        return token, transfer_time
    except Exception as e:
        format_and_print(f'2.4.Error calling recv_bc_token():{e}')


# 2.5.生成proof并发送给网关
def generate_proof_send(user_zk, user_hash_info_new, token, aes_key_to_gateway, user_socket):
    format_and_print('2.5.Start Proof Generation', '.')
    try:
        proof = user_zk.sign(user_hash_info_new, token).dump()
        proof_encrypt = aes_encrypt(aes_key_to_gateway, convert_message(proof, 'bytes'))
        send_with_header(user_socket, proof_encrypt)
        format_and_print('2.5.Successfully generated proof', "_", "center")
    except Exception as e:
        format_and_print(f'2.5.Error calling recv_bc_token():{e}')


# 2.6.接收网关的验证结果
def recv_auth_result(aes_key_to_gateway, user_socket):
    format_and_print('2.6.Start receiving authentication results', '.')
    try:
        data, transfer_time = recv_with_header(user_socket)
        result = aes_decrypt(aes_key_to_gateway, data)
        if result == b"AUTH_SUCCESS":
            auth_result = True
        else:
            auth_result = False
        format_and_print('2.6.Authentication result received successfully', "_", "center")
        return auth_result, transfer_time
    except Exception as e:
        format_and_print(f'2.6.Error calling recv_auth_result():{e}')


# 2.用户认证
def user_auth(user_socket, user_id):
    format_and_print('2.Starting the authentication process', ':')
    try:
        send_with_header(user_socket, b"USER AUTHENTICATION")  # 发送消息类型
        send_with_header(user_socket, convert_message(f"{user_id}", 'bytes'))  # 发送uid
        # 2.1.获取认证过程中使用的公钥
        aes_key = load_auth_key(user_id)
        # 零知识认证
        # 2.2.输入新的用户身份属性信息
        client_hash_info_new = user_info_generate()  # 获取网关身份信息
        # 2.3.发送网关签名
        client_zk = send_user_sign(client_hash_info_new, aes_key, user_socket)
        # 2.4.接收服务器发送的 token
        token, tt1 = recv_bc_token(user_socket, aes_key)
        # 2.5.使用 token 创建证明并发送给服务器
        generate_proof_send(client_zk, client_hash_info_new, token, aes_key, user_socket)
        # 2.6.接收服务器的验证结果
        auth_result, tt2 = recv_auth_result(aes_key, user_socket)
        if auth_result:
            format_and_print('2.User authentication success', '=', 'center')
            return auth_result, tt1, tt2
        else:
            format_and_print('2.User authentication failed')
            return None, None, None
    except Exception as e:
        format_and_print(f'2.Error calling recv_auth_result():{e}')
