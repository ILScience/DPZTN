from zerotrustnetworkelement.function import *
from zerotrustnetworkelement.encryption.ecdh import *
from zerotrustnetworkelement.blockchain.sc_function import query_gid_state, query_bc_pk, query_gw_pk, \
    query_user_hash_info, query_uid_state, update_uid_auth_state, query_gateway_pk


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


# 4.2.查询bc_pk并返回给网关
def return_bc_pk(gw_socket, loop, cli, org_admin, bc_ip, gw_id):
    format_and_print('4.2.Query bc_pk and return to gateway', '.')
    try:
        blockchain_public_key = query_bc_pk(loop, cli, org_admin, bc_ip, gw_id)
        send_with_header(gw_socket, convert_message(blockchain_public_key, 'bytes'))
        format_and_print('bc_pk sent', '-', 'center')
    except Exception as e:
        format_and_print(f'4.2.Error calling return_bc_pk():{e}')


# 4.3.加载密钥
def load_auth_key(gw_folder_path, loop, cli, org_admin, bc_ip, gw_id):
    format_and_print('4.3.Start searching for keys required for authentication', '.')
    try:
        gw_public_key = query_gw_pk(loop, cli, org_admin, bc_ip, gw_id)
        # 本地查询区块链私钥
        bc_private_key = load_key_from_file('sk_bc', gw_folder_path)
        aes_key = generate_aes_key(bc_private_key, gw_public_key)
        format_and_print('4.3.Key required for successful query authentication', "_", "center")
        return aes_key
    except Exception as e:
        format_and_print(f'4.3.Error calling load_auth_key():{e}')


# 4.4.接收用户uid
def recv_uid(gw_socket, aes_key):
    format_and_print('4.4.Start receiving uid', '.', 'left')
    try:
        data, transfer_time = recv_with_header(gw_socket)
        user_id = convert_message(aes_decrypt(aes_key, data), 'str')
        user_id = convert_message(user_id, 'UUID')
        format_and_print('4.4.Received gateway gid successfully', "_", "center")
        return user_id, transfer_time
    except Exception as e:
        format_and_print(f'4.4.Error calling recv_uid():{e}')


# 4.5.发送网关与用户通信所需的密钥
def return_keys_to_user(gw_socket, loop, cli, org_admin, bc_ip, aes_key, user_id):
    format_and_print('4.5.Start searching for keys required for authentication', '.')
    try:
        user_state = query_uid_state(loop, cli, org_admin, bc_ip, user_id)
        user_public_key = query_gateway_pk(loop, cli, org_admin, bc_ip, user_id)
        message = aes_encrypt(aes_key, convert_message(f'{user_state}||{user_public_key}', 'bytes'))
        send_with_header(gw_socket, convert_message(message, 'bytes'))
        format_and_print('4.5.Key required for successful query authentication', "_", "center")
    except Exception as e:
        format_and_print(f'4.5.Error calling return_keys_to_user():{e}')


# 4.6.将用户信息返回给网关
def send_user_info(gw_socket, user_hash_info, aes_key):
    format_and_print('4.6.Start returning user information', '.', 'left')
    try:
        message = aes_encrypt(aes_key, user_hash_info)
        send_with_header(gw_socket, message)
        format_and_print('4.6.User information returned', "_", "center")
    except Exception as e:
        format_and_print(f'4.6.Error calling send_user_info():{e}')


# 4.7.接收网关传回的注册结果
def recv_auth_result(gw_socket, aes_key):
    format_and_print('4.7.Start receiving auth result', '.', 'left')
    try:
        data, transfer_time = recv_with_header(gw_socket)
        auth_result = aes_decrypt(aes_key, data)
        format_and_print('4.7.Received auth result', "_", "center")
        return auth_result, transfer_time
    except Exception as e:
        format_and_print(f'4.7.Error calling recv_auth_result():{e}')


# 4.网关认证
def user_auth(gw_socket, loop, cli, org_admin, bc_ip):
    format_and_print('4.Starting the authentication process', ':', 'left')
    try:
        # 4.1.接收网关gid
        gw_id, gw_folder_path, tt1 = recv_gid(gw_socket)
        '''查询gid状态'''
        gid_state = query_gid_state(loop, cli, org_admin, bc_ip, gw_id)
        if gid_state == '11':
            # 4.2.查询bc_pk并返回给网关
            return_bc_pk(gw_socket, loop, cli, org_admin, bc_ip, gw_id)
            # 4.3.加载密钥
            aes_key = load_auth_key(gw_folder_path, loop, cli, org_admin, bc_ip, gw_id)
            # 4.4.接收用户uid
            user_id, tt2 = recv_uid(gw_socket, aes_key)
            user_hash_info = query_user_hash_info(loop, cli, org_admin, bc_ip, user_id)
            '''查询uid注册状态'''
            uid_state = query_uid_state(loop, cli, org_admin, bc_ip, user_id)
            if uid_state == '10':
                # 4.5.发送网关与用户通信所需的密钥
                return_keys_to_user(gw_socket, loop, cli, org_admin, bc_ip, aes_key, user_id)
                # 4.6.将用户信息返回给网关
                send_user_info(gw_socket, user_hash_info, aes_key)
                # 4.7.接收网关传回的注册结果
                auth_result, tt3 = recv_auth_result(gw_socket, aes_key)
                if auth_result == b"AUTH_SUCCESS":
                    '''更新用户认证状态'''
                    response = update_uid_auth_state(loop, cli, org_admin, bc_ip, user_id)
                    if response is True:
                        format_and_print('Success to update uid authentication state', '-', 'center')
                        format_and_print('4.Auth success', "=", "center")
                        return user_id, tt1, tt2, tt3
                    else:
                        format_and_print(f'Failed to update uid authentication state:{response}')
                else:
                    format_and_print('4.Auth failed')
                    return None, None, None, None
            elif uid_state == '00':
                format_and_print(f'{user_id} not register yet:{uid_state}')
                return None, None, None, None
            elif gid_state == '11':
                format_and_print(f'{user_id} already authentication:{uid_state}')
                return None, None, None, None
            else:
                format_and_print(f'Illegal state:{gid_state}')
                return None, None, None, None
        elif gid_state == '00':
            format_and_print(f'{gw_id} not register yet:{gid_state}')
            return None, None, None, None
        elif gid_state == '11':
            format_and_print(f'{gw_id} already authentication:{gid_state}')
            return None, None, None, None
        else:
            format_and_print(f'Illegal state:{gid_state}')
            return None, None, None, None
    except Exception as e:
        format_and_print(f'4.Error calling user_auth():{e}')
