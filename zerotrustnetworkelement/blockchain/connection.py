import socket


# import asyncio
# from hfc.fabric import Client


# 创建并启动区块链服务器
def gw_connection(server_ip, server_port):
    # 创建 socket 对象
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 绑定 IP 地址和端口
    server_socket.bind((server_ip, server_port))
    server_socket.listen(1)  # 监听连接请求
    print(f"blockchain server listening on {server_ip}:{server_port}...")
    return server_socket  # 返回服务器 socket 以供后续使用


# 关闭区块链服务器
def close_gw_connection(server_socket):
    if server_socket:
        server_socket.close()
        print("blockchain server connection closed.")

# # 连接到智能合约
# def sc_connection(net_profile_path, org):
#     cli = Client(net_profile=net_profile_path)
#     cli.new_channel('mychannel')
#     loop = asyncio.get_event_loop()
#     org_admin = cli.get_user(org, 'Admin')
#     print('blockchain connection successful!')
#     return loop, cli, org_admin
