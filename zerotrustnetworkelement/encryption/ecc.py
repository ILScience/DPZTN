from nacl.public import PrivateKey, Box
from nacl.signing import SigningKey
from nacl.encoding import Base64Encoder
from nacl.exceptions import BadSignatureError
import nacl.utils


class ECC:
    def __init__(self):
        # 初始化实例属性
        self.private_key = None
        self.public_key = None
        self.signing_key = None
        self.verify_key = None

    # 1. 生成 Curve25519 密钥对（用于密钥交换）
    def ecc_genkey(self):
        self.private_key = PrivateKey.generate()
        self.public_key = self.private_key.public_key
        return self.private_key, self.public_key

    # 2. 生成 Ed25519 签名密钥对（用于签名和验证）
    def ecc_genkey_sign(self):
        self.signing_key = SigningKey.generate()
        self.verify_key = self.signing_key.verify_key
        return self.signing_key, self.verify_key

    # 3. 加密消息（使用 Curve25519 共享密钥）
    @staticmethod
    def ecc_encrypt(sender_private_key, receiver_public_key, message):
        box = Box(sender_private_key, receiver_public_key)
        nonce = nacl.utils.random(Box.NONCE_SIZE)
        encrypted = box.encrypt(message.encode(), nonce, encoder=Base64Encoder)
        return encrypted

    # 4. 解密消息（使用 Curve25519 共享密钥）
    @staticmethod
    def ecc_decrypt(receiver_private_key, sender_public_key, encrypted_message):
        box = Box(receiver_private_key, sender_public_key)
        decrypted = box.decrypt(encrypted_message, encoder=Base64Encoder)
        return decrypted.decode()

    # 5. 签名消息（使用 Ed25519 签名）
    @staticmethod
    def ecc_sign(signing_key, message):
        try:
            signed_message = signing_key.sign(message)  # 签名并编码
            print(signed_message)
            return signed_message
        except BadSignatureError:
            print(BadSignatureError)
        except Exception as e:
            print(f"Unexpected error in ecc_sign: {e}")

    # 6. 验证消息签名（使用 Ed25519 验证）
    @staticmethod
    def ecc_verify(verify_key, signed_message):
        try:
            verify_key.verify(signed_message)  # 验证签名
            return True  # 返回验证后的原始消息
        except BadSignatureError:
            return False  # 签名验证失败
