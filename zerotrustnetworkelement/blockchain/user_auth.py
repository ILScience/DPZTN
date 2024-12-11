from zerotrustnetworkelement.function import *
from zerotrustnetworkelement.encryption.ecdh import *
from zerotrustnetworkelement.blockchain.sc_function import query_gid_state, query_bc_pk, query_gw_pk, query_gw_sig_pk, \
    query_bc_sig_pk, query_user_hash_info, query_uid_state, update_uid_auth_state


# 4.1.接收网关gid
def recv_gid(gw_socket):
    format_and_print('4.1.Start searching for keys required for authentication', '.')
    try:
        data, transfer_time = recv_with_header(gw_socket)
        gw_id = convert_message(convert_message(data, 'str'), 'UUID')
        gw_folder_path = get_folder_path('gateway' + str(gw_id))
        return gw_id, gw_folder_path, transfer_time
    except Exception as e:
        format_and_print(f'4.1.Error calling recv_gid():{e}')


# 4.2.加载密钥
def load_auth_key(gw_folder_path, loop, cli, org_admin, bc_ip, gw_id):
    format_and_print('4.2.Start searching for keys required for authentication', '.')
    try:
        '''
            加载bc_public_key,bc_verify_key, gw_public_key, gw_verify_key，user_hash_info
        '''
        bc_public_key = query_bc_pk(loop, cli, org_admin, bc_ip, gw_id)
        gw_public_key = query_gw_pk(loop, cli, org_admin, bc_ip, gw_id)
        bc_verify_key = query_bc_sig_pk(loop, cli, org_admin, bc_ip, gw_id)
        gw_verify_key = query_gw_sig_pk(loop, cli, org_admin, bc_ip, gw_id)
        # 本地查询区块链私钥
        bc_private_key = load_key_from_file('sk_bc', gw_folder_path)
        bc_sign_key = load_key_from_file('sk_sig_bc', gw_folder_path)

        aes_key = generate_aes_key(bc_private_key, gw_public_key)
        format_and_print('4.2.Key required for successful query authentication', "_", "center")
        return bc_public_key, bc_private_key, bc_verify_key, bc_sign_key, gw_public_key, gw_verify_key, aes_key
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
        message = aes_encrypt(aes_key, user_hash_info)
        send_with_header(gw_socket, message)
        format_and_print('4.4.User information returned', "_", "center")
    except Exception as e:
        format_and_print(f'4.4.Error calling send_user_info():{e}')


# 4.5.接收网关传回的注册结果
def recv_auth_result(gw_socket, aes_key):
    format_and_print('4.5.Start receiving auth result', '.', 'left')
    try:
        data, transfer_time = recv_with_header(gw_socket)
        auth_result = aes_decrypt(aes_key, data)
        format_and_print('4.5.Received auth result', "_", "center")
        return auth_result, transfer_time
    except Exception as e:
        format_and_print(f'4.5.Error calling recv_auth_result():{e}')


# 4.网关认证
def user_auth(gw_socket, loop, cli, org_admin, bc_ip):
    format_and_print('4.Starting the authentication process', ':', 'left')
    try:
        # 4.1.接收网关gid
        gw_id, gw_folder_path, tt1 = recv_gid(gw_socket)
        response = query_gid_state(loop, cli, org_admin, bc_ip, gw_id)
        '''
            查询gid状态
        '''
        # 4.2.加载密钥
        (bc_public_key, bc_private_key, bc_verify_key, bc_sign_key, gw_public_key, gw_verify_key,
         aes_key) = load_auth_key(gw_folder_path, loop, cli, org_admin, bc_ip, gw_id)
        # 4.3.接收用户uid
        user_id, tt2 = recv_uid(gw_socket, aes_key)
        user_hash_info = query_user_hash_info(loop, cli, org_admin, bc_ip, user_id)
        response = query_uid_state(loop, cli, org_admin, bc_ip, user_id)
        '''
            查询uid注册状态
        '''
        # 4.4.将用户信息返回给网关
        send_user_info(gw_socket, user_hash_info, aes_key)
        # 4.5.接收网关传回的认证结果
        auth_result, tt3 = recv_auth_result(gw_socket, aes_key)
        if auth_result == b"AUTH_SUCCESS":

            response = update_uid_auth_state(loop, cli, org_admin, bc_ip, user_id)
            '''
                更改用户认证状态
            '''
            format_and_print('4.Auth success', "=", "center")
            return user_id, aes_key, tt1, auth_result, tt2, tt3
        else:
            format_and_print('4.Auth failed')
            return None, None, None, None, None, None
    except Exception as e:
        format_and_print(f'4.Error calling user_auth():{e}')
