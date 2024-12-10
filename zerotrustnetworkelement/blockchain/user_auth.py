from zerotrustnetworkelement.function import *
from zerotrustnetworkelement.encryption.ecdh import *


# 4.1.接收网关gid
def recv_gid(gw_socket):
    format_and_print('4.1.Start searching for keys required for authentication', '.')
    try:
        data, transfer_time = recv_with_header(gw_socket)
        gid = convert_message(convert_message(data, 'str'), 'UUID')
        gw_folder_path = get_folder_path(str(gid))
        return gid, gw_folder_path, transfer_time
    except Exception as e:
        format_and_print(f'4.1.Error calling recv_gid():{e}')


# 4.2.加载密钥
def load_auth_key(gw_folder_path, user_hash_info):
    format_and_print('4.2.Start searching for keys required for authentication', '.')
    try:
        # 查询之前的网关公钥，区块链公钥
        bc_public_key = load_key_from_file('pk_bc', gw_folder_path)
        bc_private_key = load_key_from_file('sk_bc', gw_folder_path)
        bc_verify_key = load_key_from_file('pk_sig_bc', gw_folder_path)
        bc_sign_key = load_key_from_file('sk_sig_bc', gw_folder_path)
        gw_public_key = load_key_from_file('pk_gw', gw_folder_path)
        gw_verify_key = load_key_from_file('pk_sig_gw', gw_folder_path)
        # 加载用户公钥反馈给网关
        user_hash_info = convert_message(user_hash_info, 'bytes')
        aes_key = generate_aes_key(bc_private_key, gw_public_key)
        format_and_print('4.2.Key required for successful query authentication', "_", "center")
        return (bc_public_key, bc_private_key, bc_verify_key, bc_sign_key, gw_public_key, gw_verify_key, user_hash_info,
                aes_key)
    except Exception as e:
        format_and_print(f'4.2.Error calling load_auth_key():{e}')


# 4.3.接收用户uid
def recv_uid(gw_socket, aes_key):
    format_and_print('4.3.Start receiving uid', '.', 'left')
    try:
        data, transfer_time = recv_with_header(gw_socket)
        user_id = convert_message(aes_decrypt(aes_key, data), 'str')
        user_id = convert_message(user_id, 'UUID')
        format_and_print('4.3.Received gateway gid successfully', "_", "center")
        return user_id, transfer_time
    except Exception as e:
        format_and_print(f'4.3.Error calling recv_uid():{e}')


# 4.4.将用户信息返回给网关
def send_user_info(gw_socket, user_hash_info, aes_key):
    format_and_print('4.4.Start returning user information', '.', 'left')
    try:
        print(user_hash_info)
        print(type(user_hash_info))
        message = aes_encrypt(aes_key, user_hash_info)
        print(message)
        send_with_header(gw_socket, message)
        format_and_print('4.4.User information returned', "_", "center")
    except Exception as e:
        format_and_print(f'4.4.Error calling send_user_info():{e}')


# 4.5.接收网关传回的注册结果
def recv_auth_result(gw_socket):
    format_and_print('4.5.Start receiving auth result', '.', 'left')
    try:
        data, transfer_time = recv_with_header(gw_socket)
        auth_result = convert_message(data, 'str')
        format_and_print('4.5.Received auth result', "_", "center")
        return auth_result, transfer_time
    except Exception as e:
        format_and_print(f'4.5.Error calling recv_auth_result():{e}')


# 4.网关认证
def user_auth(gw_socket, user_hash_info):
    format_and_print('4.Starting the authentication process', ':', 'left')
    try:
        # 4.1.接收网关gid
        gw_id, gw_folder_path, tt1 = recv_gid(gw_socket)
        # 4.2.加载密钥
        (bc_public_key, bc_private_key, bc_verify_key, bc_sign_key, gw_public_key, gw_verify_key, user_hash_info,
         aes_key) = load_auth_key(gw_socket, user_hash_info)
        # 4.3.接收用户uid
        user_id, tt2 = recv_uid(gw_socket, aes_key)
        # 4.4.将用户信息返回给网关
        send_user_info(gw_socket, user_hash_info, aes_key)
        # 4.5.接收网关传回的注册结果
        auth_result, tt3 = recv_auth_result(gw_socket)
        format_and_print('4.Auth success', "=", "center")
        return user_id, aes_key, tt1, auth_result, tt2, tt3
    except Exception as e:
        format_and_print(f'4.Error calling user_auth():{e}')
