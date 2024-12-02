import socket
from noknow.core import ZK, ZKData


def client_program():
    server_host = "127.0.0.1"
    server_port = 10000
    client_host = "127.0.0.1"
    client_port = 10001

    # 创建客户端套接字并绑定
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.bind((client_host, client_port))

    # 初始化客户端的 ZK 实例
    client_zk = ZK.new(curve_name="secp256k1", hash_alg="sha3_256")

    # 客户端身份哈希
    identity_hash = b"client_identity"

    # 连接服务器
    client_socket.connect((server_host, server_port))
    print(f"已连接到服务器 {server_host}:{server_port}")

    # 生成签名并发送给服务器
    client_sig = client_zk.create_signature(identity_hash)
    print(client_sig)
    client_socket.sendall(client_sig.dump().encode())

    # 接收服务器生成的 token
    token = client_socket.recv(4096).decode()

    # 使用 token 生成证明并发送给服务器
    proof = client_zk.sign(identity_hash, token).dump()
    print('proof:', proof)
    print(type(proof))
    client_socket.sendall(proof.encode())
    print("已发送证明")

    # 接收认证结果
    result = client_socket.recv(4096)
    if result == b"AUTH_SUCCESS":
        print("认证成功")
    else:
        print("认证失败")

    client_socket.close()


if __name__ == "__main__":
    client_program()
