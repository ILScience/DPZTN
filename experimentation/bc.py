from zerotrustnetworkelement.encryption.ecc import *
from zerotrustnetworkelement.blockchain.connection import *
from zerotrustnetworkelement.blockchain.figure import *
from zerotrustnetworkelement.blockchain.sc_function import *
from zerotrustnetworkelement.blockchain.bc_function import *
from zerotrustnetworkelement.encryption.ecdh import *
from zerotrustnetworkelement.encryption.zkp import *


# 生成区块链的对称密钥及公私钥
def bc_key():
    ecc = ECC()
    if os.path.exists("sk_bc.key") and os.path.exists("pk_bc.key"):
        private_key = load_key_from_file("sk_bc")
        public_key = load_key_from_file('pk_bc')
    else:
        private_key, public_key = ecc.ecc_genkey()
        save_key_to_file(private_key, "sk_bc")
        save_key_to_file(public_key, 'pk_bc')

    if os.path.exists("sk_sig_bc.key") and os.path.exists("pk_sig_bc.key"):
        signing_key = load_key_from_file("sk_sig_bc")
        verify_key = load_key_from_file('pk_sig_bc')
    else:
        signing_key, verify_key = ecc.ecc_genkey_sign()
        save_key_to_file(signing_key, "sk_sig_bc")
        save_key_to_file(verify_key, 'pk_sig_bc')
    return private_key, public_key, signing_key, verify_key, ecc


# 公钥交换
def pk_exchange(client_socket, server_public_key, server_verify_key):
    try:
        send_with_header(client_socket, convert_message(server_public_key, 'bytes'))  # 发送区块链公钥
        send_with_header(client_socket, convert_message(server_verify_key, 'bytes'))  # 发送区块链认证密钥
        gateway_public_key = convert_message(recv_with_header(client_socket), 'PublicKey')  # 接收网关公钥
        gateway_verify_key = convert_message(recv_with_header(client_socket), 'VerifyKey')  # 接收网关认证密钥
        save_key_to_file(gateway_public_key, 'pk_gw')
        save_key_to_file(gateway_verify_key, 'pk_sig_gw')
        return gateway_public_key, gateway_verify_key
    except ConnectionError as conn_err:
        format_and_print(f"Connection error during key exchange: {conn_err}", chr(0x00D7), 'left')
    except ValueError as val_err:
        format_and_print(f"Value error during key exchange: {val_err}", chr(0x00D7), 'left')
    except IOError as io_err:
        format_and_print(f"File I/O error during key exchange: {io_err}", chr(0x00D7), 'left')
    except Exception as e:
        format_and_print(f"An unexpected error occurred during key exchange: {e}", chr(0x00D7), 'left')


def load_key():
    server_public_key = load_key_from_file("sk_pk")  # 加载区块链公钥
    server_private_key = load_key_from_file("sk_bc")  # 加载区块链私钥
    server_verify_key = load_key_from_file("pk_sig_bc")  # 加载区块链认证密钥
    server_sign_key = load_key_from_file('sk_sig_bc')  # 加载区块链签名密钥
    client_public_key = load_key_from_file('pk_gw')  # 加载网关公钥
    client_verify_key = load_key_from_file('pk_sig_gw')  # 加载网关认证密钥
    return server_public_key, server_private_key, server_verify_key, server_sign_key, client_public_key, client_verify_key


# 接收网关加密身份信息和网关签名
def receive_gateway_identity(client_socket, ecc, server_private_key, client_public_key):
    message1 = convert_message(recv_with_header(client_socket), 'str')
    client_hash_info, client_sig_str, timestamp = ecc.ecc_decrypt(server_private_key, client_public_key,
                                                                  message1).split("||")  # 消息解密
    client_hash_info = convert_message(client_hash_info, 'bytes')  # 将网关身份加密消息，由str转换成bytes
    client_sig = convert_message(client_sig_str, 'SignedMessage')  # 将网关签名由str转换成SignedMessage
    registration_start_time = convert_message(timestamp, 'int')  # 还原网关起始注册时间
    return client_hash_info, client_sig, registration_start_time


# 生成gid，并返回gid注册状态查询结果
def generate_and_check_gid(client_hash_info, loop, cli, org1_admin):
    gateway_id = generate_gid(convert_message(client_hash_info, 'str'))  # 生成gid
    register_state = query_register_state(loop, cli, org1_admin, '51.1.1.1',
                                          convert_message(gateway_id, 'str'))  # 查询gid注册状态
    return gateway_id, register_state


# 给网关返回gid和区块链签名
def send_gid_and_signature(client_socket, gateway_id, ecc, server_sign_key, server_private_key, client_public_key,
                           registration_start_time):
    format_and_print(f'{gateway_id} Signature Authentication Successful', '_', 'center')
    server_signature = ecc.ecc_sign(server_sign_key, gateway_id.bytes)  # 生成区块链签名
    message2 = ecc.ecc_encrypt(server_private_key, client_public_key,
                               f"{gateway_id}||{server_signature}||{registration_start_time}||{get_timestamp()}")  # 发送gid，区块链签名
    send_with_header(client_socket, convert_message(message2, 'bytes'))


# 网关身份注册
def gw_register(client_socket, ecc, loop, cli, org1_admin):
    # 加载注册过程需要使用的密钥
    server_public_key, server_private_key, server_verify_key, server_sign_key, client_public_key, client_verify_key = load_key()
    # 接收注册信息，并还原数据类型
    client_hash_info, client_sig, registration_start_time = receive_gateway_identity(client_socket, ecc,
                                                                                     server_private_key,
                                                                                     client_public_key)
    # 生成gid，并返回gid注册状态查询结果
    gateway_id, register_state = generate_and_check_gid(client_hash_info, loop, cli, org1_admin)

    # 对不同gid状态进行处理
    if register_state == f" GID {gateway_id} did not register!":
        verify_result = ecc.ecc_verify(client_verify_key, client_sig)  # 验证网关签名
        if verify_result:
            send_gid_and_signature(client_socket, gateway_id, ecc, server_sign_key, server_private_key,
                                   client_public_key, registration_start_time)  # 发送gid和区块链签名
            # 上传网关信息
            try:
                update_gw_info(loop, cli, org1_admin, '51.1.1.1', client_hash_info, convert_message(gateway_id, 'str'),
                               convert_message(client_public_key, 'str'), convert_message(client_verify_key, 'str'),
                               convert_message(verify_result, 'str'), convert_message(server_public_key, 'str'),
                               convert_message(server_verify_key, 'str'))
            except Exception as e:
                format_and_print(f'An unexpected error occurred during gateway information upload: {e}', chr(0x00D7),
                                 'left')
        return client_hash_info, gateway_id, verify_result
    # 网关已经注册
    else:
        format_and_print(f'{gateway_id} had already register', chr(0x00D7), 'left')  # 输出gid已经注册信息


def load_auth_key(loop, cli, org1_admin, client_id):
    # 查询之前的网关公钥，区块链公钥
    server_public_key = query_bc_pubkey(loop, cli, org1_admin, '51.1.1.1', convert_message(client_id, 'str'))
    server_private_key = load_key_from_file('sk_bc')
    server_verify_key = query_bc_verkey(loop, cli, org1_admin, '51.1.1.1', convert_message(client_id, 'str'))
    server_sign_key = load_key_from_file('sk_sig_bc')
    client_public_key = query_gid_pubkey(loop, cli, org1_admin, '51.1.1.1', convert_message(client_id, 'str'))
    client_verify_key = query_gid_verkey(loop, cli, org1_admin, '51.1.1.1', convert_message(client_id, 'str'))
    client_hash_info = query_gid_hashinfo(loop, cli, org1_admin, '51.1.1.1', convert_message(client_id, 'str'))
    return server_public_key, server_private_key, server_verify_key, server_sign_key, client_public_key, client_verify_key, client_hash_info


# 网关认证
def gw_auth(client_socket, loop, cli, org1_admin):
    # 接收网关gid
    message = convert_message(recv_with_header(client_socket), 'str')
    client_id = convert_message(message, 'UUID')
    auth_state = query_auth_state(loop, cli, org1_admin, '51.1.1.1', convert_message(client_id, 'str'))
    if auth_state:
        server_public_key, server_private_key, server_verify_key, server_sign_key, client_public_key, client_verify_key, client_hash_info = load_auth_key(
            loop, cli, org1_admin, client_id)
        # 利用存储在区块链的网关信息生成签名
        aes_key = generate_aes_key(server_private_key, client_public_key)
        server_zk = ZK.new(curve_name="secp384r1", hash_alg="sha3_512")
        server_signature: ZKSignature = server_zk.create_signature(client_hash_info)

        # 接收网关签名信息
        message1 = convert_message(recv_with_header(client_socket), 'str')
        a = aes_decrypt(aes_key, message1)
        b = a.decode('utf-8')
        client_sig = ZKSignature.load(b)
        client_zk = ZK(client_sig.params)

        print("Generate a signature token and send it to the client")
        token = server_zk.sign(client_hash_info, client_zk.token())
        token_encrypt = aes_encrypt(aes_key, token.dump(separator=":"))
        client_socket.sendall(token_encrypt.encode())

        print("Receive proofs sent by the client")
        proof_encrypt = client_socket.recv(1024).decode()
        proof = ZKData.load(aes_decrypt(aes_key, proof_encrypt))
        token = ZKData.load(proof.data, ":")

        print("Validating tokens and proofs")
        if not server_zk.verify(token, server_signature):
            result = b"VERIFY_FAILED"
            client_socket.sendall(aes_encrypt(aes_key, result))
        else:
            result = b"AUTH_SUCCESS"
            client_socket.sendall(
                aes_encrypt(aes_key, result) if client_zk.verify(proof, client_sig, data=token) else b"AUTH_FAILED")
        return aes_key, result


def gateway_main():
    # 生成区块链基本信息
    bc_sk, bc_pk, bc_key_sig, bc_key_vrf, ecc = bc_key()
    # 与智能合约连接
    loop, cli, org1_admin = sc_connection(net_profile_path, org='org1.example.com')
    # 与网关建立连接
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((bc_ip, bc_port))
    server_socket.listen(1)
    format_and_print(f'blockchain server listening on {bc_ip}:{bc_port}', '.', 'left')

    while True:
        try:
            gw_socket, gw_addr = server_socket.accept()  # 监听网关
        except Exception as e:
            format_and_print(f'Error in Listening Gateway:{e}', chr(0x00D7), 'left')
            # 结束进程
            continue

        # 交换密钥
        print(exchanging_publickey)
        try:
            format_and_print('Exchanging Key', '.', 'left')
            pk_exchange(gw_socket, bc_pk, bc_key_sig)
            format_and_print('Key exchange successful', '=', 'center')
        except Exception as e:
            format_and_print(f'Error in Key Exchange:{e}', chr(0x00D7), 'left')
        print(exchange_completed)

        while True:
            try:
                # 接收请求类型
                request_type = recv_with_header(gw_socket)
                format_and_print(f'Received message type: {request_type}', '-', 'center')
                # 如果接收到网关身份注册请求
                if request_type == b"REGISTRATION":
                    print(gateway_registering)
                    gw_register(gw_socket, ecc, loop, cli, org1_admin)
                    print(gateway_registration_completed)
                # 如果接收到网关身份认证请求
                elif request_type == b"AUTHENTICATION":
                    print(gateway_authentication)
                    gw_auth(gw_socket, loop, cli, org1_admin)
                    print(gateway_authentication_completed)

            except Exception as e:
                format_and_print(f'Error in receive message type:{e}', chr(0x00D7), 'left')


if __name__ == '__main__':
    gateway_main()
