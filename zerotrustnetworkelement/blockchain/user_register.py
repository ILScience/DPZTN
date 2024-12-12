from zerotrustnetworkelement.function import *
from zerotrustnetworkelement.encryption.ecdh import *
from zerotrustnetworkelement.blockchain.bc_function import *
from zerotrustnetworkelement.blockchain.sc_function import query_gid_state, query_gw_pk, register_uid, \
    query_uid_state, update_uid_reg_state


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
def load_key(loop, cli, org_admin, bc_ip, gw_id):
    format_and_print('3.2.Loading the required key for registration', '.')
    try:
        gw_folder_path = get_folder_path('gateway' + str(gw_id))
        bc_private_key = load_key_from_file('sk_bc', gw_folder_path)  # 加载区块链私钥
        gw_public_key = query_gw_pk(loop, cli, org_admin, bc_ip, gw_id)
        format_and_print('3.2.Key loaded successfully', '-', 'center')
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
        format_and_print(f'3.3.Error calling receive_user_identity():{e}')


# 3.4.发送uid给网关
def return_uid_to_gateway(bc_private_key, gw_public_key, user_id, gw_socket):
    format_and_print('3.4.Start sending uid', '.')
    try:
        aes_key = generate_aes_key(bc_private_key, gw_public_key)
        message3 = aes_encrypt(aes_key, convert_message(f'{user_id}', 'bytes'))
        send_with_header(gw_socket, message3)
        format_and_print('3.4.Send uid over.', '-', 'center')
        return aes_key
    except Exception as e:
        format_and_print(f'3.4.Error calling return_uid_to_gateway():{e}')


# 3.5.接收密钥和用户注册状态
def recv_user_info(gw_socket, aes_key):
    format_and_print('3.5.Receiving user information', '.')
    try:
        data, transfer_time = recv_with_header(gw_socket)
        message4 = aes_decrypt(aes_key, data)
        gateway_public_key, gateway_verify_key, user_pk, user_sig_pk, verify_result = message4.split('||')

        gateway_public_key = PublicKey(gateway_public_key)
        gateway_verify_key = VerifyKey(gateway_verify_key)
        user_pk = PublicKey(user_pk)
        user_sig_pk = VerifyKey(user_sig_pk)
        verify_result = bool(verify_result)

        format_and_print('3.5.User information received', '-', 'center')
        return gateway_public_key, gateway_verify_key, user_pk, user_sig_pk, verify_result
    except Exception as e:
        format_and_print(f"3.5.Unexpected error occurred in recv_user_info(): {str(e)}")


# 3.用户注册
def user_register(gw_socket, loop, cli, org_admin, bc_ip):
    try:
        # 3.1.接收gid
        gw_id = recv_gw_id(gw_socket)
        '''查询gw_id是否认证成功'''
        gid_state = query_gid_state(loop, cli, org_admin, bc_ip, gw_id)
        if gid_state == '11':
            # 3.2.加载密钥
            bc_private_key, gw_public_key = load_key(loop, cli, org_admin, bc_ip, gw_id)
            # 3.3.接收用户加密消息，生成uid
            user_hash_info, user_id, tt1 = receive_user_identity(gw_socket, bc_private_key, gw_public_key)
            '''查询user状态'''
            uid_state = query_uid_state(loop, cli, org_admin, bc_ip, user_id)
            if uid_state == '00':
                # 3.4.发送uid给网关
                aes_key = return_uid_to_gateway(bc_private_key, gw_public_key, user_id, gw_socket)
                # 3.5.接收密钥和用户注册状态
                gateway_public_key, gateway_verify_key, user_pk, user_sig_pk, verify_result = recv_user_info(gw_socket,
                                                                                                             aes_key)
                ''' 上传uid,user_hash_info，'''
                response = register_uid(loop, cli, org_admin, bc_ip, user_id, user_hash_info, gateway_public_key,
                                        gateway_verify_key, user_pk, user_sig_pk)
                if response is True:
                    format_and_print('Update uid information successful', '-', 'center')
                    '''更新用户的注册状态'''
                    response = update_uid_reg_state(loop, cli, org_admin, bc_ip, user_id, verify_result)
                    if response is True:
                        format_and_print('Update gid state successful', '-', 'center')
                        format_and_print('3.User Registration Successful', "=", "center")
                        return user_id, tt1
                else:
                    format_and_print(f'Update uid state failed:{response}')
            elif uid_state == '10':
                format_and_print(f'{user_id} already register:{uid_state}')
                return None, None
            elif gid_state == '11':
                format_and_print(f'{user_id} already authentication:{uid_state}')
                return None, None
            else:
                format_and_print(f'Illegal state:{gid_state}')
                return None, None

        elif gid_state == '00':
            format_and_print(f'{gw_id} not register yet:{gid_state}')
            return None, None
        elif gid_state == '10':
            format_and_print(f'{gw_id} not authentication yet:{gid_state}')
            return None, None
        else:
            format_and_print(f'Illegal state:{gid_state}')
            return None, None
    except Exception as e:
        format_and_print(f'3.Error calling user_register():{e}')
