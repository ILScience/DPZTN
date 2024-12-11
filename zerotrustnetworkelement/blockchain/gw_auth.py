from zerotrustnetworkelement.function import *
from zerotrustnetworkelement.encryption.ecdh import *
from noknow.core import ZK, ZKSignature, ZKData


# 2.1.接收网关gid
def recv_gw_gid(client_socket):
    format_and_print('1.Start receiving gateway gid', '.')
    try:
        data, transfer_time = recv_with_header(client_socket)
        message = convert_message(data, 'str')
        client_id = convert_message(message, 'UUID')
        format_and_print('2.1.Received gateway gid successfully', "_", "center")
        return client_id, transfer_time
    except Exception as e:
        format_and_print(f'2.1.Unexpected error in recv_gw_gid():{str(e)}')


# 2.2.加载密钥
def load_auth_key(client_hash_info, client_id):
    format_and_print('2.2.Start searching for keys required for authentication', '.')
    try:
        folder_path = get_folder_path('gateway' + str(client_id))
        # 查询之前的网关公钥，区块链公钥
        server_public_key = load_key_from_file('pk_bc', folder_path)
        server_private_key = load_key_from_file('sk_bc', folder_path)
        server_verify_key = load_key_from_file('pk_sig_bc', folder_path)
        server_sign_key = load_key_from_file('sk_sig_bc', folder_path)
        client_public_key = load_key_from_file('pk_gw', folder_path)
        client_verify_key = load_key_from_file('pk_sig_gw', folder_path)
        client_hash_info = client_hash_info
        format_and_print('2.2.Key required for successful query authentication', "_", "center")
        return (server_public_key, server_private_key, server_verify_key, server_sign_key,
                client_public_key, client_verify_key, client_hash_info)
    except Exception as e:
        format_and_print(f'2.2.Unexpected error in load_auth_key():{e}')


# 2.3.利用存储在区块链的网关信息生成签名
def generate_bc_sign(server_private_key, client_public_key, client_hash_info):
    format_and_print('2.3.Signature being generated from gid store information', '.')
    try:
        aes_key = generate_aes_key(server_private_key, client_public_key)
        server_zk = ZK.new(curve_name="secp384r1", hash_alg="sha3_512")
        server_signature: ZKSignature = server_zk.create_signature(client_hash_info)
        format_and_print('2.3.Successfully generated signature based on gid store information', "_", "center")
        return aes_key, server_zk, server_signature
    except Exception as e:
        format_and_print(f'2.3.Unexpected error in generate_bc_sign():{e}')


# 2.4.接收网关签名信息
def recv_gw_sign(client_socket, aes_key):
    format_and_print('2.4.Receiving gateway signature message', '.')
    try:
        data, transfer_time = recv_with_header(client_socket)
        message1 = aes_decrypt(aes_key, data)
        client_sig = convert_message(message1, 'ZKSignature')
        client_zk = ZK(client_sig.params)
        format_and_print('2.4.Successfully received gateway signature message', "_", "center")
        return client_sig, client_zk, transfer_time
    except Exception as e:
        format_and_print(f'2.4.Unexpected error in recv_gw_sign():{e}')


# 2.5.生成签名令牌并发送给网关
def generate_token_and_send(server_zk, client_hash_info, client_zk, aes_key, client_socket):
    format_and_print('2.5.Signature token being generated', '.')
    try:
        token = server_zk.sign(client_hash_info, client_zk.token())
        token_encrypt = aes_encrypt(aes_key, convert_message(token.dump(separator=":"), 'bytes'))
        send_with_header(client_socket, convert_message(token_encrypt, 'bytes'))
        format_and_print('2.5.Successfully generated signature token', "_", "center")
        return token
    except Exception as e:
        format_and_print(f'2.5.Unexpected error in generate_token_and_send():{e}')


# 2.6.接收网关发送的proof
def recv_gw_proof(client_socket, aes_key):
    format_and_print('2.6.Receiving gateway proof', '.')
    try:

        data, transfer_time = recv_with_header(client_socket)
        a = convert_message(aes_decrypt(aes_key, data), 'str')
        proof = ZKData.load(a)
        token = ZKData.load(proof.data, ":")
        format_and_print('2.6.Successfully received gateway proof', "_", "center")
        return proof, token, transfer_time
    except Exception as e:
        format_and_print(f'2.6.Unexpected error in recv_gw_proof():{e}')


# 2.7 验证网关发送的令牌
def verify_gw_token(server_zk, token, server_signature, client_socket, aes_key, client_zk, proof, client_sig):
    format_and_print('2.7.Verifying gateway token', '.')
    try:
        if not server_zk.verify(token, server_signature):
            result = b"VERIFY_FAILED"
            send_with_header(client_socket, aes_encrypt(aes_key, result))
            format_and_print('2.7.Gateway Token Authentication Failed')
        else:
            if client_zk.verify(proof, client_sig, data=token):
                result = b"AUTH_SUCCESS"
                send_with_header(client_socket, aes_encrypt(aes_key, result))
                format_and_print('2.7.Gateway Token Authentication Successful', "_", "center")
            else:
                result = b"AUTH_FAILED"
                send_with_header(client_socket, aes_encrypt(aes_key, result))
                format_and_print('2.7.Gateway Token Authentication Failed')
        return result
    except Exception as e:
        format_and_print(f'2.7.Error calling recv_gw_proof():{e}')


# 2.网关认证
def gw_auth(client_socket, client_hash_info):
    format_and_print('2.Starting the authentication process', ':')
    try:
        # 2.1.接收网关gid
        client_id, tt1 = recv_gw_gid(client_socket)
        '''
            查询gid网关注册状态
        '''
        # 2.2.加载密钥
        '''
            加载网关公钥，区块链公钥，网关认证公钥，区块链认证公钥，client_hash_info
        '''
        (server_public_key, server_private_key, server_verify_key, server_sign_key, client_public_key,
         client_verify_key, client_hash_info) = load_auth_key(client_hash_info, client_id)
        # 2.3.利用存储在区块链的网关信息生成签名
        aes_key, server_zk, server_signature = generate_bc_sign(server_private_key, client_public_key,
                                                                client_hash_info)
        # 2.4.接收网关签名信息
        client_sig, client_zk, tt2 = recv_gw_sign(client_socket, aes_key)
        # 2.5.生成签名令牌并发送给网关
        generate_token_and_send(server_zk, client_hash_info, client_zk, aes_key, client_socket)
        # 2.6.接收网关发送的proof
        proof, token, tt3 = recv_gw_proof(client_socket, aes_key)
        # 2.7 验证网关发送的令牌
        result = verify_gw_token(server_zk, token, server_signature, client_socket, aes_key, client_zk, proof,
                                 client_sig)
        if result == b"AUTH_SUCCESS":
            '''
                更改认证状态
            '''
            format_and_print('2.Successful authentication', '=', 'center')
            return client_id, result, tt1, tt2, tt3
        else:
            format_and_print('2.Failed to authentication')
            return None, None, None, None, None
    except Exception as e:
        format_and_print(f'2.Authentication Error:{e}')
