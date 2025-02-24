from zerotrustnetworkelement.encryption.ecdh import *
from zerotrustnetworkelement.function import *
from scapy.all import rdpcap


# 3.1.加载密钥
def load_auth_key(user_id):
    format_and_print('3.1.Loading the required key for auth', '.')
    try:
        user_folder_path = get_folder_path('user' + str(user_id))
        user_private_key = load_key_from_file("sk_user", user_folder_path)  # 加载用户私钥
        gateway_public_key = load_key_from_file("pk_gateway", user_folder_path)  # 加载网关公钥
        aes_key_to_gateway = generate_aes_key(user_private_key, gateway_public_key)  # 生成会话密钥
        format_and_print('3.1.Key loaded successfully', '-', 'center')
        return aes_key_to_gateway
    except Exception as e:
        format_and_print(f'3.1.Error in load_auth_key():{str(e)}')


# 3.2.发送用户信息
def send_user_info(user_socket, user_id, aes_key):
    format_and_print('3.2.Send user information.', '.')
    try:
        send_with_header(user_socket, convert_message(f"{user_id}", "bytes"))
        user_role = input('请输入您的角色')
        user_request_resource = input('请输入您想获取的资源编号')
        message1 = aes_encrypt(aes_key, user_role)
        message2 = aes_encrypt(aes_key, user_request_resource)
        send_with_header(user_socket, message1)
        send_with_header(user_socket, message2)
        format_and_print("3.2.Send message success", '-', 'center')
    except Exception as e:
        format_and_print(f'3.2.Error in send_user_info():{str(e)}')


# 3.3.接收资源
def recv_resource(user_socket, aes_key):
    format_and_print('3.3.Receiving resources.', '.')
    try:
        data1, tt_u1 = recv_with_header(user_socket)
        resource = aes_decrypt(aes_key, convert_message(data1, "bytes"))
        format_and_print("3.3.Resource received successfully", '-', 'center')
        return resource
    except Exception as e:
        format_and_print(f'3.1.Error in load_auth_key():{str(e)}')


# 3.4.发送消息
def send_message(user_socket, pcap_file):
    format_and_print('3.4.Send user information.', '.')
    try:
        packets = rdpcap(pcap_file)
        for packet in packets:
            # 获取包的原始数据
            raw_data = bytes(packet)
            # 发送数据包到服务器
            user_socket.sendall(raw_data)
            print(f"3.4.Sent packet of length {len(raw_data)} to server")
    except Exception as e:
        print(f"3.4.Error while sending data: {e}")


# 3.用户访问控制
def user_access(user_socket, user_id, pcap_file):
    format_and_print('3.User start access request.', ':')
    try:
        # 3.1.加载密钥
        aes_key = load_auth_key(user_id)
        # 3.2.发送用户信息
        send_user_info(user_socket, user_id, aes_key)
        # 3.3.接收资源
        resource = recv_resource(user_socket, aes_key)
        # 3.4.发送消息
        send_message(user_socket, pcap_file)
        format_and_print("3.User success access", '=', 'center')
    except Exception as e:
        format_and_print(f'3.Error in user_access():{e}')
