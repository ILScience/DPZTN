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
    """
    使用 AES 密钥解密密文

    :param aes_key: AES 密钥对象 (例如，`cryptography.hazmat.primitives.ciphers.AES`)
    :param ciphertext: 密文，字节串类型 (bytes)

    :return: 解密后的明文，字节串类型 (bytes)
    """
    try:
        if aes_key is None:
            raise ValueError("AES 密钥未生成，请调用 generate_aes_key() 方法")
        plaintext = aes_key.decrypt(ciphertext)
        return plaintext
    except KeyboardInterrupt as k:
        print('KeyboardInterrupt:', k)
    except ValueError as v:
        print('ValueError:', v)
    except TypeError as t:
        print('TypeError:', t)
    except IndexError as i:
        print('IndexError:', i)
    except AttributeError as a:
        print('AttributeError:', a)
