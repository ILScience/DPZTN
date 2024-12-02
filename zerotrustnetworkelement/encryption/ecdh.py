from nacl.public import Box
import nacl.utils


def generate_aes_key(sk, pk):
    aes_key = Box(sk, pk)
    return aes_key


def aes_encrypt(aes_key, plaintext):
    if aes_key is None:
        raise ValueError("AES 密钥未生成，请调用 generate_aes_key() 方法")
    nonce = nacl.utils.random(Box.NONCE_SIZE)
    ciphertext = aes_key.encrypt(plaintext, nonce)
    return ciphertext


def aes_decrypt(aes_key, ciphertext):
    if aes_key is None:
        raise ValueError("AES 密钥未生成，请调用 generate_aes_key() 方法")
    plaintext = aes_key.decrypt(ciphertext)
    return plaintext
