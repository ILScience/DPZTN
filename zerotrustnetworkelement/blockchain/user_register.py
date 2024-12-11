from zerotrustnetworkelement.function import *
from zerotrustnetworkelement.encryption.ecdh import *
from zerotrustnetworkelement.blockchain.bc_function import *
from zerotrustnetworkelement.blockchain.sc_function import query_gid_state, query_gw_pk, update_uid_info, \
    update_uid_reg_state, query_uid_state


# 3.1.接收gid
def recv_gw_id(gw_socket):
    format_and_print('3.1.Receiving gateway id', '.')
    try:
        data, transfer_time = recv_with_header(gw_socket)
        gw_id = convert_message(convert_message(data, 'str'), 'UUID')

        return gw_id
    except Exception as e:
        format_and_print(f'3.1.Error calling recv_gw_id():{e}')


# 3.2.加载密钥
def load_key(gw_socket, gw_id):
    format_and_print('3.1.Loading the required key for registration', '.')
    try:
        gw_folder_path = get_folder_path('gateway' + str(gw_id))
        bc_private_key = load_key_from_file('sk_bc', gw_folder_path)  # 加载区块链私钥
        gw_public_key = load_key_from_file('pk_gw', gw_folder_path)  # 加载网关公钥
        format_and_print('3.1.Key loaded successfully', '-', 'center')
        return bc_private_key, gw_public_key

    except Exception as e:
        format_and_print(f'3.1.Error calling load_key():{e}')


# 3.3.接收用户加密消息，生成uid
def receive_user_identity(gw_socket, bc_private_key, gw_public_key):
    format_and_print('3.3.Start receiving user encrypted identities and user signatures', '.')
    try:
        aes_key = generate_aes_key(bc_private_key, gw_public_key)  # 生成aes密钥

        data, transfer_time = recv_with_header(gw_socket)
        user_hash_info = convert_message(aes_decrypt(aes_key, data), 'str')  # 消息解密
        user_id = generate_gid(user_hash_info)  # 将用户身份加密消息，由str转换成bytes

        format_and_print('3.3.User encrypted identity information and user signature received successfully', '-',
                         'center')
        return user_hash_info, user_id, transfer_time

    except Exception as e:
        format_and_print(f'3.2.Error calling receive_user_identity():{e}')


# 3.4.发送uid给网关
def return_uid_to_gateway(bc_private_key, gw_public_key, user_id, gw_socket):
    format_and_print('3.4.Start sending uid', '.')
    try:
        aes_key = generate_aes_key(bc_private_key, gw_public_key)
        message3 = aes_encrypt(aes_key, convert_message(f'{user_id}', 'bytes'))
        send_with_header(gw_socket, message3)
        format_and_print('3.4.Send uid over.', '-', 'center')

    except Exception as e:
        format_and_print(f'3.4.Error calling return_uid_to_gateway():{e}')


# 3.用户注册
def user_register(gw_socket, loop, cli, org_admin, bc_ip):
    try:
        # 3.1.接收gid
        gw_id = recv_gw_id(gw_socket)
        response = query_gid_state(loop, cli, org_admin, bc_ip, gw_id)
        '''
            查询gw_id是否认证成功
        '''
        # 3.2.加载密钥
        gw_public_key = query_gw_pk(loop, cli, org_admin, bc_ip, gw_id)
        '''
            加载gid的gw_public_key
        '''
        bc_private_key, gw_public_key = load_key(gw_socket, gw_id)
        # 3.3.接收用户加密消息，生成uid
        user_hash_info, user_id, tt1 = receive_user_identity(gw_socket, bc_private_key, gw_public_key)
        response = query_uid_state(loop, cli, org_admin, bc_ip, user_id)
        '''
            查询uid状态
        '''
        # 3.4.发送uid给网关
        return_uid_to_gateway(bc_private_key, gw_public_key, user_id, gw_socket)

        response = update_uid_info(loop, cli, org_admin, bc_ip, user_id, user_hash_info)
        user_reg_result = recv_gw_id(gw_socket)
        response = update_uid_reg_state(loop, cli, org_admin, bc_ip, user_id)
        '''
            上传uid,user_hash_info，
            接收用户注册状态，更改用户的注册状态
        '''
        return user_hash_info, user_id, tt1
    except Exception as e:
        format_and_print(f'3.Error calling user_register():{e}')
