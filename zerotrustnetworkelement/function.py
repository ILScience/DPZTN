import os
import struct
import time
import nacl
from nacl.public import PrivateKey
import json
import ast
from nacl.signing import SignedMessage, VerifyKey, SigningKey
from nacl.public import PublicKey
import uuid
import noknow
from noknow.core import ZKSignature, ZKData
import csv


def format_and_print(text, symbol, alignment):
    """
    格式化并打印文字和符号的组合，总长度为 100 个字符。

    :param text: str, 输入的文字
    :param symbol: str, 用于填充的符号，取第一个字符
    :param alignment: str, 对齐方式 ('left', 'center')
    """
    # 限制总长度
    total_length = 100
    text_length = len(text)

    # 检查文字长度是否超出限制
    if text_length > total_length:
        return "文字过长"

    # 剩余的填充符号长度
    fill_length = total_length - text_length

    # 对齐逻辑
    if alignment == 'left':
        result = text + symbol[0] * fill_length
    elif alignment == 'center':
        left_fill = fill_length // 2
        right_fill = fill_length - left_fill
        result = symbol[0] * left_fill + text + symbol[0] * right_fill
    else:
        raise ValueError("Invalid alignment. Choose from 'left' or 'center'.")

    # 打印结果
    print(result)


# 保存密钥到本地文件
def save_key_to_file(key, filename):
    # 根据密钥类型判断文件后缀
    if isinstance(key, (PrivateKey, SigningKey)):  # 假设 PrivateKey 是私钥类
        file_path = f'./{filename}.key'
        key_type = 'private'
    elif isinstance(key, (PublicKey, VerifyKey)):  # 假设 PublicKey 是公钥类
        file_path = f'./{filename}.pub'
        key_type = 'public'
    else:
        raise ValueError("The key must be an instance of PrivateKey, SigningKey or PublicKey, VerifyKey.")

    # 确保目录存在
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    try:
        # 保存密钥到文件
        with open(file_path, 'wb') as key_file:
            key_file.write(bytes(key))  # 假设密钥对象支持 bytes() 转换
        print(f'{key_type.capitalize()} key saved to {file_path}')
    except Exception as e:
        raise ValueError(f"Failed to save {key_type} key to {file_path}: {e}")


def load_key_from_file(filename):
    private_key_path = f'./{filename}.key'
    public_key_path = f'./{filename}.pub'

    # 判断是否是 .key 文件
    if os.path.exists(private_key_path):
        try:
            with open(private_key_path, 'rb') as key_file:
                key_data = key_file.read()

            # 根据文件名判断是 SigningKey 还是 PrivateKey
            if 'sig' in filename.lower():
                key = SigningKey(key_data)  # 假设 SigningKey 可通过字节数据初始化
            else:
                key = PrivateKey(key_data)  # 假设 PrivateKey 可通过字节数据初始化
            return key
        except Exception as e:
            raise ValueError(f"Failed to load key from {private_key_path}: {e}")

    # 判断是否是 .pub 文件
    if os.path.exists(public_key_path):
        try:
            with open(public_key_path, 'rb') as key_file:
                key_data = key_file.read()

            # 根据文件名判断是 VerifyKey 还是 PublicKey
            if 'sig' in filename.lower():
                key = VerifyKey(key_data)  # 假设 VerifyKey 可通过字节数据初始化
            else:
                key = PublicKey(key_data)  # 假设 PublicKey 可通过字节数据初始化
            return key
        except Exception as e:
            raise ValueError(f"Failed to load key from {public_key_path}: {e}")

    # 如果文件都不存在
    raise FileNotFoundError(f"Neither private key nor public key file found for {filename}.")


def convert_message(message, target_type):
    """
    转换消息为目标数据类型

    :param message: 输入消息
    :param target_type: 目标类型，可以是 "bytes", "PublicKey", "VerifyKey", "str", "SignedMessage", "int", "UUID"
    :return: 转换后的目标数据
    """
    try:
        if target_type == 'bytes':
            # 将字符串转换为字节
            if isinstance(message, str):
                if message.startswith("b'") or message.startswith('b"'):
                    # 字符串包含 b'' 表示字节格式
                    try:
                        return ast.literal_eval(message)  # 安全解析
                    except (SyntaxError, ValueError):
                        raise ValueError(f"Invalid byte literal: {message}")
                else:
                    return message.encode('utf-8')  # 直接转换为 UTF-8 字节
            elif isinstance(message, noknow.core.ZKSignature):
                return message.dump().encode('utf-8')
            # 将整数转换为字节
            elif isinstance(message, int):
                return message.to_bytes((message.bit_length() + 7) // 8, byteorder="big") or b"\x00"
            # 将字典或列表转换为字节（JSON 编码）
            elif isinstance(message, (dict, list)):
                return json.dumps(message).encode("utf-8")
            # 将 PublicKey 转换为字节
            elif isinstance(message, nacl.public.PublicKey):
                return bytes(message)
            # 将 VerifyKey 转换为字节
            elif isinstance(message, nacl.signing.VerifyKey):
                return bytes(message)
            # 如果输入已经是字节，直接返回
            elif isinstance(message, (bytes, bytearray)):
                return message
            else:
                raise ValueError(f"Cannot convert type {type(message)} to bytes")

        elif target_type == 'PublicKey':
            # 将字节转换为 PublicKey
            if isinstance(message, bytes):
                return PublicKey(message)
            else:
                raise ValueError(f"Cannot convert type {type(message)} to PublicKey")

        elif target_type == 'VerifyKey':
            # 将字节转换为 VerifyKey
            if isinstance(message, bytes):
                return VerifyKey(message)
            else:
                raise ValueError(f"Cannot convert type {type(message)} to VerifyKey")

        elif target_type == 'SignedMessage':
            # 将字符串转换为 SignedMessage
            if isinstance(message, str):
                try:
                    message_bytes = ast.literal_eval(message)  # 将字符串解析为字节
                    if not isinstance(message_bytes, (bytes, bytearray)):
                        raise ValueError(f"String did not evaluate to bytes: {message}")
                    return SignedMessage(message_bytes)  # 转换为 SignedMessage
                except (SyntaxError, ValueError):
                    raise ValueError(f"Invalid string format for SignedMessage: {message}")
            else:
                raise ValueError(f"Cannot convert type {type(message)} to SignedMessage")

        elif target_type == 'ZKSignature':
            if isinstance(message, bytes):
                try:
                    message_str = message.decode('utf-8')
                    return ZKSignature.load(message_str)
                except (SyntaxError, ValueError):
                    raise ValueError(f"Invalid string format for SignedMessage: {message}")
            else:
                raise ValueError(f"Cannot convert type {type(message)} to ZKSignature")

        elif target_type == 'ZKData':
            if isinstance(message, bytes):
                try:
                    message_str = message.decode('utf-8')
                    return ZKData.load(message_str, separator=":")
                except (SyntaxError, ValueError):
                    raise ValueError(f"Invalid string format for ZKData: {message}")
            else:
                raise ValueError(f"Cannot convert type {type(message)} to ZKData")

        elif target_type == 'str':
            # 将 JSON 转换为字符串
            if isinstance(message, (dict, list)):
                return json.dumps(message)  # 将 Python 对象序列化为 JSON 字符串
            elif isinstance(message, (bytes, bytearray)):
                try:
                    return message.decode('utf-8')  # 尝试使用 UTF-8 解码
                except UnicodeDecodeError:
                    return message.decode('utf-8', errors='replace')  # 替代解码错误的字节
            elif isinstance(message, str):
                return message  # 如果已经是字符串，直接返回
            elif isinstance(message, uuid.UUID):
                return str(message)  # 将 UUID 转换为字符串
            else:
                raise ValueError(f"Cannot convert type {type(message)} to str")

        elif target_type == 'int':
            # 将字符串转换为整数
            if isinstance(message, str):
                try:
                    return int(message)  # 转换字符串为整数
                except ValueError:
                    raise ValueError(f"Cannot convert string to int: {message}")
            elif isinstance(message, int):
                return message  # 如果已经是整数，直接返回
            else:
                raise ValueError(f"Cannot convert type {type(message)} to int")

        elif target_type == 'UUID':
            # 将字符串转换为 UUID
            if isinstance(message, str):
                try:
                    return uuid.UUID(message)  # 将字符串转换为 UUID
                except ValueError:
                    raise ValueError(f"Cannot convert string to UUID: {message}")
            elif isinstance(message, uuid.UUID):
                return message  # 如果已经是 UUID，直接返回
            else:
                raise ValueError(f"Cannot convert type {type(message)} to UUID")

        else:
            raise ValueError(f"Unsupported target type: {target_type}")

    except Exception as e:
        raise ValueError(f"Error converting message to {target_type}: {e}")


def send_with_header(sock, message):
    # 获取消息长度并编码为固定长度头部
    header = convert_message(f"{len(message):08}", 'bytes')  # 8 字节固定长度头部
    timestamp = get_timestamp()
    timestamp_data = struct.pack("d", timestamp)
    # 发送头部和数据
    sock.sendall(header + timestamp_data + message)


def recv_with_header(sock):
    # 先接收固定长度的头部
    data = b""
    while len(data) < 8:
        packet = sock.recv(8 - len(data))
        if not packet:
            raise ConnectionError("Connection closed before header received")
        data += packet

    # 解析消息长度
    message_length = int(data.decode("utf-8"))

    # 接收时间戳数据（8字节）
    timestamp_data = sock.recv(8)
    timestamp = struct.unpack("d", timestamp_data)[0]  # 解包时间戳

    # 接收消息体
    data = b""
    while len(data) < message_length:
        packet = sock.recv(message_length - len(data))
        if not packet:
            raise ConnectionError("Connection closed during data reception")
        data += packet

    end_time = get_timestamp()
    transfer_time = end_time - timestamp
    print(f"Link transmission time: {transfer_time:.6f} ns")

    return data, transfer_time


# 时间戳函数
def get_timestamp():
    timestamp = time.perf_counter() * 1_000_000_000  # 转换为纳秒
    return timestamp


def append_to_json(filename, time_dict):
    try:
        filename = convert_message(filename, 'str')
        filepath = os.path.join(os.getcwd(), filename + '.json')
        if os.path.exists(filepath):
            with open(filepath, 'r') as json_file:
                data = json.load(json_file)
                if data is None:
                    data = [time_dict]
                else:
                    data.append(time_dict)
        else:
            data = [time_dict]

        with open(filepath, "w") as json_file:
            json.dump(data, json_file, indent=4)

    except Exception as e:
        print(e)


# 监控资源的函数
def monitor_resources(process, output_file="resource_usage.csv", duration=10):
    start_time = time.time()

    # 如果文件存在，先删除它，确保覆盖
    if os.path.exists(output_file):
        os.remove(output_file)
        print(f"{output_file} 已存在，已被删除，准备创建新的文件。")

    # 打开CSV文件并准备写入
    with open(output_file, mode='w', newline='') as csvfile:
        fieldnames = ['timestamp', 'cpu_usage', 'memory_usage']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # 写入CSV文件头
        writer.writeheader()

        # 记录资源占用情况
        while time.time() - start_time < duration:
            # 获取CPU占用百分比，等待0.1秒
            cpu_usage = process.cpu_percent(interval=0.1)
            # 获取内存使用情况，单位MB
            memory_usage = process.memory_info().rss / (1024 * 1024)

            # 获取当前时间戳
            timestamp = time.time() - start_time

            # 写入到CSV文件
            writer.writerow(
                {'timestamp': round(timestamp, 2), 'cpu_usage': cpu_usage, 'memory_usage': round(memory_usage, 2)})

            # # 打印到控制台（可选）
            # print(f"CPU使用率: {cpu_usage}% | 内存使用: {memory_usage:.2f} MB")
