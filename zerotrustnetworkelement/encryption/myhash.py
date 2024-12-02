import hashlib


# 生成哈希值的方法
def hash_encrypt(data, salt=None):
    """
    生成哈希值
    :param data: 待加密数据（字符串类型）
    :param salt: 盐值（可选，默认为 None）
    :return: 哈希值，包含盐值（如果提供了盐）
    """
    if salt is None:
        # 无盐情况下的哈希
        hash_obj = hashlib.sha256(data.encode())
        return hash_obj.digest()
    else:
        # 使用盐值的哈希
        hash_obj = hashlib.sha256(salt + data.encode())
        return salt + hash_obj.digest()  # 保存盐值以便验证


# 验证哈希的方法
def hash_verify(data, hash_value):
    """
    验证哈希值
    :param data: 待验证数据（字符串类型）
    :param hash_value: 已生成的哈希值（可以包含盐）
    :return: 布尔值，表示验证是否成功
    """
    # 检查哈希值是否包含盐值
    if len(hash_value) == 32:  # 无盐的哈希值长度为 32 字节
        expected_hash = hashlib.sha256(data.encode()).digest()
    else:
        salt = hash_value[:16]  # 提取前 16 字节为盐值
        expected_hash = hashlib.sha256(salt + data.encode()).digest()
        expected_hash = salt + expected_hash  # 组合盐值和哈希值

    return expected_hash == hash_value  # 验证哈希是否匹配
