from zerotrustnetworkelement.function import *
from zerotrustnetworkelement.encryption.ecdh import *
from noknow.core import ZK, ZKSignature, ZKData


# 4.1.接收用户uid
def recv_uid(user_socket):
    format_and_print('4.1.Start receiving uid', '.')
    try:
        data, tt_u = recv_with_header(user_socket)
        message = convert_message(data, 'str')
        user_id = convert_message(message, 'UUID')
        format_and_print('4.1.Received uid successfully', "_", "center")
        return user_id, tt_u

    except Exception as e:
        format_and_print(f'4.1.Error calling recv_uid():{e}')


# 4.2.加载密钥
def load_auth_key(user_id, gw_id):
    format_and_print('4.2.Start searching for keys required for authentication', '.')
    try:
        # 查询之前的网关公钥，区块链公钥
        gw_folder_path = get_folder_path('gateway' + str(gw_id))
        blockchain_public_key = load_key_from_file('pk_bc', gw_folder_path)
        blockchain_verify_key = load_key_from_file('pk_sig_bc', gw_folder_path)
        gw_public_key = load_key_from_file('pk_gw', gw_folder_path)
        gw_private_key = load_key_from_file('sk_gw', gw_folder_path)
        gw_verify_key = load_key_from_file('pk_sig_gw', gw_folder_path)
        gw_sign_key = load_key_from_file('sk_sig_gw', gw_folder_path)
        aes_key_to_bc = generate_aes_key(gw_private_key, blockchain_public_key)

        user_folder_path = get_folder_path('user' + str(user_id))
        gateway_public_key = load_key_from_file('pk_gateway', user_folder_path)
        gateway_private_key = load_key_from_file('sk_gateway', user_folder_path)
        gateway_verify_key = load_key_from_file('pk_sig_gateway', user_folder_path)
        gateway_sign_key = load_key_from_file('sk_sig_gateway', user_folder_path)
        user_public_key = load_key_from_file('pk_user', user_folder_path)
        user_verify_key = load_key_from_file('pk_sig_user', user_folder_path)  # 加载用户认证密钥
        aes_key_to_user = generate_aes_key(gateway_private_key, user_public_key)

        format_and_print('4.2.Key required for successful query authentication', "_", "center")
        return (blockchain_public_key, blockchain_verify_key, gw_public_key, gw_private_key, gw_verify_key, gw_sign_key,
                aes_key_to_bc, gateway_public_key, gateway_private_key, gateway_verify_key, gateway_sign_key,
                user_public_key, user_verify_key, aes_key_to_user)

    except Exception as e:
        format_and_print(f'4.2.Error calling recv_uid():{e}')


# 4.3.发送请求类型，并将gid和uid发送给区块链
def send_gid_uid(aes_key_to_bc, gw_id, user_id, gw_socket):
    format_and_print('4.3.Start sending gid and uid', '.', 'left')
    try:
        send_with_header(gw_socket, b"USER AUTHENTICATION")  # 发送消息类型
        send_with_header(gw_socket, convert_message(f'{gw_id}', 'bytes'))
        message = aes_encrypt(aes_key_to_bc, convert_message(f'{user_id}', 'bytes'))
        send_with_header(gw_socket, message)
        format_and_print('4.3.Send gid and uid over.', "_", "center")

    except Exception as e:
        format_and_print(f'4.3.Error calling send_gid_uid():{e}')


# 4.4.从区块链接收用户信息
def recv_user_info(gw_socket, aes_key_to_bc):
    format_and_print('4.4.Start receiving user information', '.', 'left')
    try:
        data, tt_b = recv_with_header(gw_socket)
        message = aes_decrypt(aes_key_to_bc, data)
        user_hash_info = convert_message(message, 'str')
        format_and_print('4.4.User information received', "_", "center")
        return user_hash_info, tt_b

    except Exception as e:
        format_and_print(f'4.4.Error calling recv_user_info():{e}')


# 4.5.利用接收到的的网关信息生成网关签名
def generate_bc_sign(gateway_private_key, user_public_key, user_hash_info):
    format_and_print('4.5.Signature being generated from gid store information', '.', 'left')
    try:
        aes_key_to_user = generate_aes_key(gateway_private_key, user_public_key)
        gateway_zk = ZK.new(curve_name="secp384r1", hash_alg="sha3_512")
        gateway_signature: ZKSignature = gateway_zk.create_signature(user_hash_info)
        format_and_print('4.5.Successfully generated signature based on gid store information', "_", "center")
        return aes_key_to_user, gateway_zk, gateway_signature

    except Exception as e:
        format_and_print(f'4.5.Error calling generate_bc_sign():{e}')


# 4.6.接收用户签名信息
def recv_gateway_sign(user_socket, aes_key_to_user):
    format_and_print('4.6.Receiving gateway signature message', '.')
    try:
        data, tt_u = recv_with_header(user_socket)
        message1 = aes_decrypt(aes_key_to_user, data)
        user_sig = convert_message(message1, 'ZKSignature')
        user_zk = ZK(user_sig.params)
        format_and_print('4.6.Successfully received gateway signature message', "_", "center")
        return user_sig, user_zk, tt_u

    except Exception as e:
        format_and_print(f'4.6.Error calling recv_gateway_sign():{e}')


# 4.7.生成签名令牌并发送给网关
def generate_token_and_send(gateway_zk, user_hash_info, user_zk, aes_key_to_user, user_socket):
    format_and_print('4.7.Signature token being generated', '.', 'left')
    try:
        token = gateway_zk.sign(user_hash_info, user_zk.token())
        token_encrypt = aes_encrypt(aes_key_to_user, convert_message(token.dump(separator=":"), 'bytes'))
        send_with_header(user_socket, convert_message(token_encrypt, 'bytes'))
        format_and_print('4.7.Successfully generated signature token', "_", "center")

    except Exception as e:
        format_and_print(f'4.7.Error calling generate_token_and_send():{e}')


# 4.8.接收网关发送的proof
def recv_gw_proof(user_socket, aes_key_to_user):
    format_and_print('4.8.Receiving gateway proof', '.')
    try:
        data, tt_u = recv_with_header(user_socket)
        a = convert_message(aes_decrypt(aes_key_to_user, data), 'str')
        proof = ZKData.load(a)
        token = ZKData.load(proof.data, ":")
        format_and_print('4.8.Successfully received gateway proof', "_", "center")
        return proof, token, tt_u

    except Exception as e:
        format_and_print(f'4.8.Error calling recv_gw_proof():{e}')


# 4.9.验证网关发送的令牌
def verify_gw_token(gateway_zk, token, gateway_signature, user_socket, gw_socket, aes_key_to_user, aes_key_to_bc,
                    user_zk, proof, user_sig):
    format_and_print('4.9.Verifying gateway token', '.')
    try:
        if not gateway_zk.verify(token, gateway_signature):
            result = b"VERIFY_FAILED"
            send_with_header(user_socket, aes_encrypt(aes_key_to_user, result))
            format_and_print('4.9.Gateway Token Authentication Failed')
        else:
            if user_zk.verify(proof, user_sig, data=token):
                result = b"AUTH_SUCCESS"
                send_with_header(user_socket, aes_encrypt(aes_key_to_user, result))
                send_with_header(gw_socket, aes_encrypt(aes_key_to_bc, result))
                format_and_print('4.9.Gateway Token Authentication Successful', "_", "center")

            else:
                result = b"AUTH_FAILED"
                send_with_header(user_socket, aes_encrypt(aes_key_to_user, result))
                send_with_header(gw_socket, aes_encrypt(aes_key_to_bc, result))
                format_and_print('4.9.Gateway Token Authentication Failed')
        return result
    except Exception as e:
        format_and_print(f'4.9.Error calling verify_gw_token():{e}')


# 3 网关认证
def user_auth(user_socket, gw_socket, gw_id):
    format_and_print('4.Starting the user authentication process', ':', 'left')
    try:
        # 4.1.接收用户uid
        user_id, tt_u1 = recv_uid(user_socket)
        # 4.2.加载密钥
        (blockchain_public_key, blockchain_verify_key, gw_public_key, gw_private_key,
         gw_verify_key, gw_sign_key, aes_key_to_bc, gateway_public_key, gateway_private_key,
         gateway_verify_key, gateway_sign_key, user_public_key, user_verify_key, aes_key_to_user) = load_auth_key(
            user_id, gw_id)
        # 4.3.发送请求类型，并将gid和uid发送给区块链
        send_gid_uid(aes_key_to_bc, gw_id, user_id, gw_socket)
        # 4.4.从区块链接收用户信息
        user_hash_info, tt_b1 = recv_user_info(gw_socket, aes_key_to_bc)
        # 4.5.利用接收到的的网关信息生成网关签名
        aes_key_to_user, gateway_zk, gateway_signature = generate_bc_sign(gateway_private_key, user_public_key,
                                                                          user_hash_info)
        # 4.6.接收用户签名信息
        user_sig, user_zk, tt_u2 = recv_gateway_sign(user_socket, aes_key_to_user)
        # 4.7.生成签名令牌并发送给网关
        generate_token_and_send(gateway_zk, user_hash_info, user_zk, aes_key_to_user, user_socket)
        # 4.8.接收网关发送的proof
        proof, token, tt_u3 = recv_gw_proof(user_socket, aes_key_to_user)
        verify_result = verify_gw_token(gateway_zk, token, gateway_signature, user_socket, gw_socket, aes_key_to_user,
                                        aes_key_to_bc, user_zk, proof, user_sig)
        if verify_result == b"AUTH_SUCCESS":
            format_and_print('4.Successful authentication', '=', 'center')
            return user_id, aes_key_to_user, verify_result, tt_u1, tt_b1, tt_u2, tt_u3
        else:
            format_and_print('4.Failed to authentication')
            return None, None, None, None, None, None, None
    except Exception as e:
        format_and_print(f'4.Error calling user_auth():{e}')
