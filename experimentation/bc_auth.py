import socket
from noknow.core import ZK, ZKSignature, ZKData


def server_program():
    host = "127.0.0.1"
    port = 10000

    # 创建服务器套接字
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)

    print(f"服务器运行在 {host}:{port}，等待客户端连接...")

    # 初始化服务器的 ZK 实例
    server_zk = ZK.new(curve_name="secp256k1", hash_alg="sha3_256")
    server_signature: ZKSignature = server_zk.create_signature(host)

    while True:
        conn, addr = server_socket.accept()
        print(f"客户端已连接: {addr}")

        # 接收客户端身份哈希和签名
        data = conn.recv(4096).decode()
        client_sig = ZKSignature.load(data)
        print('client_sig:', client_sig)
        client_zk = ZK(client_sig.params)

        # 生成 token 并发送给客户端
        token = server_zk.sign(host, client_zk.token())
        print('token:', token)
        conn.sendall(token.dump(separator=":").encode())
        print("Token 已发送")

        # 接收客户端的证明
        proof_data = conn.recv(4096).decode()
        proof = ZKData.load(proof_data)
        print('proof:', proof)
        print(type(proof))
        token = ZKData.load(proof.data, ":")
        print(token)
        print(type(token))

        # 验证签名
        if not server_zk.verify(token, server_signature):
            print("签名验证失败")
            conn.sendall(b"VERIFY_FAILED")
            conn.close()
            continue
        print("签名验证成功")

        if client_zk.verify(proof, client_sig, data=token):
            conn.sendall(b"AUTH_SUCCESS")
            print("认证成功")
        else:
            conn.sendall(b"AUTH_FAILED")
            print("认证失败")


if __name__ == "__main__":
    server_program()
