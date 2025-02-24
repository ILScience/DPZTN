from zerotrustnetworkelement.function import *
from zerotrustnetworkelement.encryption.ecdh import *


# 5.1.接收用户uid
def recv_uid(user_socket):
    format_and_print('5.1.Start receiving uid', '.')
    try:
        data, tt_u = recv_with_header(user_socket)
        message = convert_message(data, 'str')
        user_id = convert_message(message, 'UUID')
        format_and_print('5.1.Received uid successfully', "_", "center")
        return user_id, tt_u
    except Exception as e:
        format_and_print(f'4.1.Error calling recv_uid():{e}')


# 5.2.发送请求类型，发送gid给区块链
def send_gid(gw_id, gw_socket):
    format_and_print('5.2.Start sending gid', '.')
    try:
        send_with_header(gw_socket, b"USER ACCESS")  # 发送消息类型
        send_with_header(gw_socket, convert_message(f'{gw_id}', 'bytes'))
        format_and_print('5.2.Send gid over.', "_", "center")
    except Exception as e:
        format_and_print(f'5.2.Error calling send_gid():{e}')


# 5.3.接收区块链公钥并生成会话密钥
def load_aes_key_to_bc(gw_socket, gw_id):
    format_and_print('5.3.Start searching for keys required for authentication', '.')
    try:
        # 查询之前的网关公钥，区块链公钥
        data, tt_b = recv_with_header(gw_socket)
        blockchain_public_key = PublicKey(convert_message(data, 'bytes'))
        gw_folder_path = get_folder_path('gateway' + str(gw_id))
        gw_private_key = load_key_from_file('sk_gw', gw_folder_path)
        aes_key_to_bc = generate_aes_key(gw_private_key, blockchain_public_key)
        format_and_print('5.3.Key required for successful query authentication', "_", "center")
        return aes_key_to_bc, tt_b
    except Exception as e:
        format_and_print(f'5.3.Error calling load_aes_key_to_bc():{e}')


# 5.4.将uid发送给区块链
def send_uid(aes_key_to_bc, user_id, gw_socket):
    format_and_print('5.4.Start sending uid', '.')
    try:
        message = aes_encrypt(aes_key_to_bc, convert_message(f'{user_id}', 'bytes'))
        send_with_header(gw_socket, message)
        format_and_print('5.4.Send uid over.', "_", "center")
    except Exception as e:
        format_and_print(f'5.4.Error calling send_uid():{e}')


# 5.5.加载密钥和用户状态
def load_keys_to_user(gw_socket, user_id, aes_key_to_bc):
    format_and_print('5.5.Start searching for keys required for authentication', '.')
    try:
        data, tt_b = recv_with_header(gw_socket)
        message = aes_decrypt(aes_key_to_bc, convert_message(data, "bytes"))
        user_state, user_public_key = convert_message(message, 'str').split('||')
        user_public_key = PublicKey(convert_message(user_public_key, "bytes"))

        user_folder_path = get_folder_path('user' + str(user_id))
        gateway_private_key = load_key_from_file('sk_gateway', user_folder_path)

        print(gateway_private_key, type(gateway_private_key))
        print(user_public_key, type(user_public_key))
        aes_key_to_user = generate_aes_key(gateway_private_key, user_public_key)
        format_and_print('5.5.Key required for successful query authentication', "_", "center")
        return user_state, aes_key_to_user, tt_b
    except Exception as e:
        format_and_print(f'5.5.Error calling load_keys_to_user():{e}')


# 5.6.获取用户角色和访问资源
def recv_user_info(user_socket, aes_key_to_user):
    format_and_print('5.6.Getting user roles and access to resources', '.')
    try:
        data1, tt_u1 = recv_with_header(user_socket)
        data2, tt_u2 = recv_with_header(user_socket)
        message1 = aes_decrypt(aes_key_to_user, convert_message(data1, "bytes"))
        message2 = aes_decrypt(aes_key_to_user, convert_message(data2, "bytes"))
        user_role = message1
        user_request_resource = message2
        format_and_print('5.6. Successful acquisition of user information', "_", "center")
        return user_role, user_request_resource, tt_u1, tt_u2
    except Exception as e:
        format_and_print(f'5.6.Error calling recv_user_info():{e}')


# 5.7.将用户请求信息转发给区块链
def send_user_info(gateway_socket, aes_key_to_bc, user_role, user_request_resource):
    format_and_print('5.7.Forwarding user request information to the blockchain', '.')
    try:
        message1 = aes_encrypt(aes_key_to_bc, user_role)
        message2 = aes_encrypt(aes_key_to_bc, user_request_resource)
        send_with_header(gateway_socket, message1)
        send_with_header(gateway_socket, message2)
        format_and_print('5.7. Forwarded user information successfully', "_", "center")
    except Exception as e:
        format_and_print(f'5.7.Error calling send_user_info():{e}')


# 5.8.接收用户资源
def recv_resource(gw_socket, aes_key_to_bc):
    format_and_print('5.8.Receive user resources', '.')
    try:
        data1, tt_b = recv_with_header(gw_socket)
        resource = aes_decrypt(aes_key_to_bc, convert_message(data1, "bytes"))
        format_and_print('5.7. User resource received successfully', "_", "center")
        return resource, tt_b
    except Exception as e:
        format_and_print(f'5.4.Error calling recv_resource():{e}')


# 5.9.返回用户资源给用户
def send_resource(user_socket, aes_key_to_user, resource):
    format_and_print('5.Returning user resources to the user', '.')
    try:
        message1 = aes_encrypt(aes_key_to_user, resource)
        send_with_header(user_socket, message1)
        format_and_print('5.7. User resources returned successfully', "_", "center")
    except Exception as e:
        format_and_print(f'5.4.Error calling send_resource():{e}')


# 5.用户访问控制流程
def user_access(gw_socket, user_socket, gw_id):
    format_and_print('5.Starting the user access control process.', ':')
    try:
        # 5.1.接收用户uid
        user_id, tt_u1 = recv_uid(user_socket)
        # 5.2.发送请求类型，发送gid给区块链
        send_gid(gw_id, gw_socket)
        # 5.3.接收区块链公钥并生成会话密钥
        aes_key_to_bc, tt_b1, = load_aes_key_to_bc(gw_socket, gw_id)
        # 5.4.将uid发送给区块链
        send_uid(aes_key_to_bc, user_id, gw_socket)
        # 5.5.加载密钥和用户状态
        user_state, aes_key_to_user, tt_b2 = load_keys_to_user(gw_socket, user_id, aes_key_to_bc)
        # 5.6.获取用户角色和访问资源
        user_role, user_request_resource, tt_u2, tt_u3 = recv_user_info(user_socket, aes_key_to_user)
        # 5.7.将用户请求信息转发给区块链
        send_user_info(gw_socket, aes_key_to_bc, user_role, user_request_resource)
        # 5.8.接收用户资源
        resource, tt_b3 = recv_resource(gw_socket, aes_key_to_bc)
        # 5.9.返回用户资源给用户
        send_resource(user_socket, aes_key_to_user, resource)
        format_and_print(f'5.User Access Control Process Success', "=", "center")
    except Exception as e:
        format_and_print(f'5.Error calling user_access():{e}')
