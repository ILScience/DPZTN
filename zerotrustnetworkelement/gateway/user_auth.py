from zerotrustnetworkelement.function import *
from zerotrustnetworkelement.encryption.ecdh import *
from noknow.core import ZK, ZKSignature, ZKData


# 3.1 接收用户uid
def recv_uid(client_socket):
    format_and_print('3.1 Start receiving uid', '.', 'left')
    try:
        data, transfer_time = recv_with_header(client_socket)
        message = convert_message(data, 'str')
        user_id = convert_message(message, 'UUID')
        format_and_print('3.1 Received uid successfully', "_", "center")
        return user_id, transfer_time
    except KeyboardInterrupt as k:
        print('3.1 KeyboardInterrupt:', k)
    except ValueError as v:
        print('3.1 ValueError:', v)
    except TypeError as t:
        print('3.1 TypeError:', t)
    except IndexError as i:
        print('3.1 IndexError:', i)
    except AttributeError as a:
        print('3.1 AttributeError:', a)
    except FileExistsError as f:
        print('3.1 FileExistsError:', f)


# 3.2 加载密钥
def load_auth_key():
    format_and_print('3.2 Start searching for keys required for authentication', '.', 'left')
    try:
        # 查询之前的网关公钥，区块链公钥
        blockchain_public_key = load_key_from_file('pk_bc')
        blockchain_verify_key = load_key_from_file('pk_sig_bc')
        gw_public_key = load_key_from_file('pk_gw')
        gw_private_key = load_key_from_file('sk_gw')
        gw_verify_key = load_key_from_file('pk_sig_gw')
        gw_sign_key = load_key_from_file('sk_sig_gw')
        aes_key_to_bc = generate_aes_key(gw_private_key, blockchain_public_key)

        blockchain_public_key = load_key_from_file('pk_bc')
        gw_private_key = load_key_from_file('sk_gw')
        aes_key_to_bc = generate_aes_key(gw_private_key, blockchain_public_key)

        gateway_public_key = load_key_from_file('pk_gateway')
        gateway_private_key = load_key_from_file('sk_gateway')
        gateway_verify_key = load_key_from_file('pk_sig_gateway')
        gateway_sign_key = load_key_from_file('sk_sig_gateway')
        user_public_key = load_key_from_file('pk_user')
        user_verify_key = load_key_from_file('pk_sig_user')  # 加载用户认证密钥
        aes_key_to_user = generate_aes_key(gateway_private_key, user_public_key)

        format_and_print('3.2 Key required for successful query authentication', "_", "center")
        return (blockchain_public_key, blockchain_verify_key, gw_public_key, gw_private_key,
                gw_verify_key, gw_sign_key, aes_key_to_bc, gateway_public_key, gateway_private_key,
                gateway_verify_key, gateway_sign_key, user_public_key, user_verify_key, aes_key_to_user)
    except KeyboardInterrupt as k:
        print('3.2 KeyboardInterrupt:', k)
    except ValueError as v:
        print('3.2 ValueError:', v)
    except TypeError as t:
        print('3.2 TypeError:', t)
    except IndexError as i:
        print('3.2 IndexError:', i)
    except AttributeError as a:
        print('3.2 AttributeError:', a)
    except FileExistsError as f:
        print('3.2 FileExistsError:', f)


# 3.3 发送请求类型，并将gid和uid发送给区块链
def send_gid_uid(aes_key_to_bc, gateway_id, user_id, gateway_socket):
    format_and_print('3.3 Start sending gid and uid', '.', 'left')
    try:
        send_with_header(gateway_socket, b"USER AUTHENTICATION")  # 发送消息类型
        message = aes_encrypt(aes_key_to_bc, convert_message(f'{gateway_id}||{user_id}', 'bytes'))
        send_with_header(gateway_socket, message)
        format_and_print('3.3 Send gid and uid over.', "_", "center")
    except KeyboardInterrupt as k:
        print('3.3 KeyboardInterrupt:', k)
    except ValueError as v:
        print('3.3 ValueError:', v)
    except TypeError as t:
        print('3.3 TypeError:', t)
    except IndexError as i:
        print('3.3 IndexError:', i)
    except AttributeError as a:
        print('3.3 AttributeError:', a)
    except FileExistsError as f:
        print('3.3 FileExistsError:', f)


# 3.4 从区块链接收用户信息
def recv_user_info(gateway_socket, aes_key_to_bc):
    format_and_print('3.4 Start receiving user information', '.', 'left')
    try:
        data, tt_b = recv_with_header(gateway_socket)
        message = aes_decrypt(aes_key_to_bc, data)
        user_hash_info = convert_message(message, 'str')
        format_and_print('3.4 User information received', "_", "center")
        return user_hash_info, tt_b
    except KeyboardInterrupt as k:
        print('3.4 KeyboardInterrupt:', k)
    except ValueError as v:
        print('3.4 ValueError:', v)
    except TypeError as t:
        print('3.4 TypeError:', t)
    except IndexError as i:
        print('3.4 IndexError:', i)
    except AttributeError as a:
        print('3.4 AttributeError:', a)
    except FileExistsError as f:
        print('3.4 FileExistsError:', f)


# 3.5 利用接收到的的网关信息生成网关签名
def generate_bc_sign(gateway_private_key, user_public_key, user_hash_info):
    format_and_print('3.5 Signature being generated from gid store information', '.', 'left')
    try:
        aes_key_to_user = generate_aes_key(gateway_private_key, user_public_key)
        gateway_zk = ZK.new(curve_name="secp384r1", hash_alg="sha3_512")
        gateway_signature: ZKSignature = gateway_zk.create_signature(user_hash_info)
        format_and_print('3.5 Successfully generated signature based on gid store information', "_", "center")
        return aes_key_to_user, gateway_zk, gateway_signature
    except KeyboardInterrupt as k:
        print('3.5 KeyboardInterrupt:', k)
    except ValueError as v:
        print('3.5 ValueError:', v)
    except TypeError as t:
        print('3.5 TypeError:', t)
    except IndexError as i:
        print('3.5 IndexError:', i)
    except AttributeError as a:
        print('3.5 AttributeError:', a)
    except FileExistsError as f:
        print('3.5 FileExistsError:', f)


# 3.6 接收用户签名信息
def recv_gw_sign(user_socket, aes_key_to_user):
    format_and_print('3.6 Receiving gateway signature message', '.', 'left')
    try:
        data, transfer_time = recv_with_header(user_socket)
        message1 = aes_decrypt(aes_key_to_user, data)
        user_sig = convert_message(message1, 'ZKSignature')
        user_zk = ZK(user_sig.params)
        format_and_print('3.6 Successfully received gateway signature message', "_", "center")
        return user_sig, user_zk, transfer_time

    except KeyboardInterrupt as k:
        print('3.6 KeyboardInterrupt:', k)
    except ValueError as v:
        print('3.6 ValueError:', v)
    except TypeError as t:
        print('3.6 TypeError:', t)
    except IndexError as i:
        print('3.6 IndexError:', i)
    except AttributeError as a:
        print('3.6 AttributeError:', a)
    except FileExistsError as f:
        print('3.6 FileExistsError:', f)


# 3.7 生成签名令牌并发送给网关
def generate_token_and_send(gateway_zk, user_hash_info, user_zk, aes_key_to_user, user_socket):
    format_and_print('3.7 Signature token being generated', '.', 'left')
    try:
        token = gateway_zk.sign(user_hash_info, user_zk.token())
        token_encrypt = aes_encrypt(aes_key_to_user, convert_message(token.dump(separator=":"), 'bytes'))
        send_with_header(user_socket, convert_message(token_encrypt, 'bytes'))
        format_and_print('3.7 Successfully generated signature token', "_", "center")
    except KeyboardInterrupt as k:
        print('3.7 KeyboardInterrupt:', k)
    except ValueError as v:
        print('3.7 ValueError:', v)
    except TypeError as t:
        print('3.7 TypeError:', t)
    except IndexError as i:
        print('3.7 IndexError:', i)
    except AttributeError as a:
        print('3.7 AttributeError:', a)
    except FileExistsError as f:
        print('3.7 FileExistsError:', f)


# 3.8 接收网关发送的proof
def recv_gw_proof(user_socket, aes_key_to_user):
    format_and_print('3.8 Receiving gateway proof', '.', 'left')
    try:

        data, transfer_time = recv_with_header(user_socket)
        a = convert_message(aes_decrypt(aes_key_to_user, data), 'str')
        proof = ZKData.load(a)
        token = ZKData.load(proof.data, ":")
        format_and_print('3.8 Successfully received gateway proof', "_", "center")
        return proof, token, transfer_time
    except KeyboardInterrupt as k:
        print('3.8 KeyboardInterrupt:', k)
    except ValueError as v:
        print('3.8 ValueError:', v)
    except TypeError as t:
        print('3.8 TypeError:', t)
    except IndexError as i:
        print('3.8 IndexError:', i)
    except AttributeError as a:
        print('3.8 AttributeError:', a)
    except FileExistsError as f:
        print('3.8 FileExistsError:', f)


# 3.7 验证网关发送的令牌
def verify_gw_token(gateway_zk, token, gateway_signature, user_socket, gateway_socket, aes_key_to_user, aes_key_to_bc,
                    user_zk, proof, user_sig):
    format_and_print('3.9 Verifying gateway token', '.', 'left')
    try:
        if not gateway_zk.verify(token, gateway_signature):
            result = b"VERIFY_FAILED"
            send_with_header(user_socket, aes_encrypt(aes_key_to_user, result))
            format_and_print('3.9 Gateway Token Authentication Failed', chr(0x00D7), "left")
        else:
            if user_zk.verify(proof, user_sig, data=token):
                result = b"AUTH_SUCCESS"
                send_with_header(user_socket, aes_encrypt(aes_key_to_user, result))
                send_with_header(gateway_socket, aes_encrypt(aes_key_to_bc, result))
                format_and_print('3.9 Gateway Token Authentication Successful', "_", "center")
            else:
                result = b"AUTH_FAILED"
                send_with_header(user_socket, aes_encrypt(aes_key_to_user, result))
                send_with_header(gateway_socket, aes_encrypt(aes_key_to_bc, result))
                format_and_print('3.9 Gateway Token Authentication Failed', chr(0x00D7), "left")
        return result
    except KeyboardInterrupt as k:
        print('3.9 KeyboardInterrupt:', k)
    except ValueError as v:
        print('3.9 ValueError:', v)
    except TypeError as t:
        print('3.9 TypeError:', t)
    except IndexError as i:
        print('3.9 IndexError:', i)
    except AttributeError as a:
        print('3.9 AttributeError:', a)
    except FileExistsError as f:
        print('3.9 FileExistsError:', f)


# 3 网关认证
def user_auth(user_socket, gateway_socket, gid):
    format_and_print('3.Starting the user authentication process', ':', 'left')
    try:
        # 接收用户uid
        user_id, tt_u1 = recv_uid(user_socket)
        (blockchain_public_key, blockchain_verify_key, gw_public_key, gw_private_key,
         gw_verify_key, gw_sign_key, aes_key_to_bc, gateway_public_key, gateway_private_key,
         gateway_verify_key, gateway_sign_key, user_public_key, user_verify_key, aes_key_to_user) = load_auth_key()
        send_gid_uid(aes_key_to_bc, gid, user_id, gateway_socket)
        user_hash_info, tt_b1 = recv_user_info(gateway_socket, aes_key_to_bc)

        aes_key_to_user, server_zk, server_signature = generate_bc_sign(gateway_private_key, user_public_key,
                                                                        user_hash_info)  # 利用存储在区块链的网关信息生成签名
        client_sig, client_zk, tt_u2 = recv_gw_sign(user_socket, aes_key_to_user)  # 接收网关签名信息
        generate_token_and_send(server_zk, user_hash_info, client_zk, aes_key_to_user, user_socket)  # 生成签名令牌并发送给网关
        proof, token, tt_u3 = recv_gw_proof(user_socket, aes_key_to_user)  # 接收网关发送的proof
        result = verify_gw_token(server_zk, token, server_signature, user_socket, gateway_socket, aes_key_to_user,
                                 aes_key_to_bc, client_zk, proof, client_sig)
        format_and_print('3.Successful authentication', '=', 'center')
        return user_id, aes_key_to_user, result, tt_u1, tt_b1, tt_u2, tt_u3

    except KeyboardInterrupt as k:
        print('3 KeyboardInterrupt:', k)
    except ValueError as v:
        print('3 ValueError:', v)
    except TypeError as t:
        print('3 TypeError:', t)
    except IndexError as i:
        print('3 IndexError:', i)
    except AttributeError as a:
        print('3 AttributeError:', a)
    except FileExistsError as f:
        print('3 FileExistsError:', f)
