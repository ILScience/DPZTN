import time
import uuid

# 生成GID
def generate_gid(text):
    gid = uuid.uuid3(uuid.NAMESPACE_DNS, text)
    return gid


# 生成UID
def generate_uid(text):
    uid = uuid.uuid3(uuid.NAMESPACE_DNS, text)
    return uid


def get_timestamp():
    timestamp = int(time.time() * 1000)
    return timestamp


# 保存 AES 密钥到文件
def save_aes_key(aes_key, filename):
    with open(filename, "wb") as file:
        file.write(aes_key)
    print(f"AES key saved to {filename}")

# 从文件加载 AES 密钥
def load_aes_key(filename):
    with open(filename, "rb") as file:
        aes_key = file.read()
    print(f"AES key loaded from {filename}")
    return aes_key

