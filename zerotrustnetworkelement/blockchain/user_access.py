from zerotrustnetworkelement.function import *
from zerotrustnetworkelement.encryption.ecdh import *
from zerotrustnetworkelement.blockchain.sc_function import query_bc_pk, query_gw_pk, query_uid_state, query_user_pk, \
    query_gid_state, query_resource, query_gid_mark,query_uid_mark


# 5.1.接收网关gid
def recv_gid(gw_socket):
    format_and_print('5.1.Start searching for keys required for authentication', '.')
    try:
        data, transfer_time = recv_with_header(gw_socket)
        gw_id = convert_message(convert_message(data, 'str'), 'UUID')
        gw_folder_path = get_folder_path('gateway' + str(gw_id))
        return gw_id, gw_folder_path, transfer_time
    except Exception as e:
        format_and_print(f'5.1.Error calling recv_gid():{e}')


# 5.2.查询bc_pk并返回给网关
def return_bc_pk(gw_socket, loop, cli, org_admin, bc_ip, gw_id):
    format_and_print('5.2.Query bc_pk and return to gateway', '.')
    try:
        blockchain_public_key = query_bc_pk(loop, cli, org_admin, bc_ip, gw_id)
        send_with_header(gw_socket, convert_message(blockchain_public_key, 'bytes'))
        format_and_print('bc_pk sent', '-', 'center')
    except Exception as e:
        format_and_print(f'5.2.Error calling return_bc_pk():{e}')


# 5.3.加载会话密钥
def load_auth_key(gw_folder_path, loop, cli, org_admin, bc_ip, gw_id):
    format_and_print('5.3.Start searching for keys required for authentication', '.')
    try:
        gw_public_key = query_gw_pk(loop, cli, org_admin, bc_ip, gw_id)
        gw_public_key = PublicKey(convert_message(gw_public_key, "bytes"))
        # 本地查询区块链私钥
        bc_private_key = load_key_from_file('sk_bc', gw_folder_path)
        aes_key = generate_aes_key(bc_private_key, gw_public_key)
        format_and_print('5.3.Key required for successful query authentication', "_", "center")
        return aes_key
    except Exception as e:
        format_and_print(f'5.3.Error calling load_auth_key():{e}')


# 5.4.接收用户uid
def recv_uid(gw_socket, aes_key):
    format_and_print('5.4.Start receiving uid', '.', 'left')
    try:
        data, transfer_time = recv_with_header(gw_socket)
        user_id = convert_message(aes_decrypt(aes_key, data), 'str')
        user_id = convert_message(user_id, 'UUID')
        format_and_print('5.4.Received gateway gid successfully', "_", "center")
        return user_id, transfer_time
    except Exception as e:
        format_and_print(f'5.4.Error calling recv_uid():{e}')


# 5.5.发送网关与用户通信所需的密钥
def return_keys_to_user(gw_socket, loop, cli, org_admin, bc_ip, aes_key, user_id):
    format_and_print('5.5.Start searching for keys required for authentication', '.')
    try:
        user_state = query_uid_state(loop, cli, org_admin, bc_ip, user_id)
        user_public_key = query_user_pk(loop, cli, org_admin, bc_ip, user_id)
        message = aes_encrypt(aes_key, convert_message(f'{user_state}||{user_public_key}', 'bytes'))
        send_with_header(gw_socket, convert_message(message, 'bytes'))
        format_and_print('5.5.Key required for successful query authentication', "_", "center")
    except Exception as e:
        format_and_print(f'5.5.Error calling return_keys_to_user():{e}')


# 5.6.获取用户角色和访问资源
def recv_user_info(gw_socket, aes_key):
    format_and_print('5.6.Getting user roles and access to resources', '.')
    try:
        data1, tt_u1 = recv_with_header(gw_socket)
        data2, tt_u2 = recv_with_header(gw_socket)
        message1 = aes_decrypt(aes_key, convert_message(data1, "bytes"))
        message2 = aes_decrypt(aes_key, convert_message(data2, "bytes"))
        user_role = message1
        user_request_resource = message2
        format_and_print('5.6.Getting user roles and accessing resources succeeded', "_", "center")
        return user_role, user_request_resource, tt_u1, tt_u2
    except Exception as e:
        format_and_print(f'5.6.Error calling recv_user_info():{e}')


# 5.7.返回资源
def return_resource(gw_socket, aes_key, resource):
    format_and_print('5.6.Return to Resources', '.')
    try:
        data = aes_encrypt(aes_key, convert_message(resource, 'bytes'))
        message = send_with_header(gw_socket, convert_message(data, 'bytes'))
        format_and_print('5.6.Return resource success', "_", "center")
    except Exception as e:
        format_and_print(f'5.6.Error calling return_resource():{e}')


# 5.用户访问控制流程
def user_access(gw_socket, loop, cli, org_admin, bc_ip):
    format_and_print('5.Starting the user access control process.', ':')
    try:
        # 5.1.接收网关gid
        gw_id, gw_folder_path, tt1 = recv_gid(gw_socket)
        gid_state = query_gid_state(loop, cli, org_admin, bc_ip, gw_id)
        gw_reputation, gw_risk = query_gid_mark(loop, cli, org_admin, bc_ip, gw_id).split("+++")
        # 5.2.查询bc_pk并返回给网关
        aes_key = load_auth_key(gw_folder_path, loop, cli, org_admin, bc_ip, gw_id)
        # 5.3.加载会话密钥
        return_bc_pk(gw_socket, loop, cli, org_admin, bc_ip, gw_id)
        # 5.4.接收用户uid
        user_id, tt2 = recv_uid(gw_socket, aes_key)
        uid_state = query_uid_state(loop, cli, org_admin, bc_ip, user_id)
        user_reputation, user_risk ,user_bh_score= query_uid_mark(loop, cli, org_admin, bc_ip, gw_id).split("+++")
        # 计算用户行为分数，网关信誉值和风险值
        # 5.5.发送网关与用户通信所需的密钥
        return_keys_to_user(gw_socket, loop, cli, org_admin, bc_ip, aes_key, user_id)
        # 5.6.获取用户角色和访问资源
        user_role, user_request_resource, tt3, tt4 = recv_user_info(gw_socket, aes_key)
        # 5.7.返回资源
        resource = query_resource(loop, cli, org_admin, bc_ip, user_id, user_role, user_request_resource)
        format_and_print('5.6.user access control success', "=", "center")
        return_resource(gw_socket, aes_key, resource)
    except Exception as e:
        format_and_print(f'5.Error calling user_access():{e}')
