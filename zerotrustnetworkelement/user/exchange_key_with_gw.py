from zerotrustnetworkelement.encryption.ecc import *
from zerotrustnetworkelement.function import *


def user_key():
    ecc = ECC()
    private_key, public_key = ecc.ecc_genkey()
    signing_key, verify_key = ecc.ecc_genkey_sign()
    return private_key, public_key, signing_key, verify_key, ecc



# 与网关建立连接并交换公钥
def pk_exchange(client_socket, client_public_key, client_verify_key):
    format_and_print('1.Exchanging Key', ':', 'left')
    try:
        exchange_key_start_time = get_timestamp()

        data, transfer_time1 = recv_with_header(client_socket)
        server_public_key = convert_message(data, 'PublicKey')  # 接收区块链公钥
        data, transfer_time2 = recv_with_header(client_socket)
        server_verify_key = convert_message(data, 'VerifyKey')  # 接收区块链验证公钥

        send_with_header(client_socket, convert_message(client_public_key, 'bytes'))  # 发送网关公钥
        send_with_header(client_socket, convert_message(client_verify_key, 'bytes'))

        exchange_key_end_time = get_timestamp()
        format_and_print('1.Key exchange successful', '=', 'center')

        exchange_key_duration = exchange_key_end_time - exchange_key_start_time
        return server_public_key, server_verify_key, transfer_time1, transfer_time2, exchange_key_duration
    except ConnectionError as conn_err:
        format_and_print(f"Connection error during key exchange: {conn_err}", chr(0x00D7), 'left')
    except ValueError as val_err:
        format_and_print(f"Value error during key exchange: {val_err}", chr(0x00D7), 'left')
    except IOError as io_err:
        format_and_print(f"File I/O error during key exchange: {io_err}", chr(0x00D7), 'left')
    except Exception as e:
        format_and_print(f"An unexpected error occurred during key exchange: {e}", chr(0x00D7), 'left')
