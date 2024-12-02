import socket


def start_gateway_client(client_ip, client_port, server_ip, server_port):
    # 创建 socket 对象
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.bind((client_ip, client_port))
    # 连接到区块链服务器
    client_socket.connect((server_ip, server_port))
    print(f"Connected to blockchain server at {server_ip}:{server_port} from {client_ip}:{client_port}")
    return client_socket  # 返回客户端 socket 以供后续使用
