from zerotrustnetworkelement.encryption.ecc import *
from zerotrustnetworkelement.function import *


def gw_key():
    ecc = ECC()
    if os.path.exists("../../experimentation/gw/sk_gw.key") and os.path.exists("../../experimentation/gw/pk_gw.pub"):
        private_key = load_key_from_file("sk_gw")
        public_key = load_key_from_file('pk_gw')
    else:
        private_key, public_key = ecc.ecc_genkey()
        save_key_to_file(private_key, "sk_gw")
        save_key_to_file(public_key, 'pk_gw')

    if os.path.exists("../../experimentation/gw/sk_sig_gw.key") and os.path.exists(
            "../../experimentation/gw/pk_sig_gw.pub"):
        signing_key = load_key_from_file("sk_sig_gw")
        verify_key = load_key_from_file('pk_sig_gw')
    else:
        signing_key, verify_key = ecc.ecc_genkey_sign()
        save_key_to_file(signing_key, "sk_sig_gw")
        save_key_to_file(verify_key, 'pk_sig_gw')
    return private_key, public_key, signing_key, verify_key, ecc


# 与区块链建立连接并交换公钥
def pk_exchange(client_socket, client_public_key, client_verify_key):
    format_and_print('1.Exchanging Key', '.', 'left')
    try:
        exchange_key_start_time = get_timestamp()

        data, transfer_time1 = recv_with_header(client_socket)
        server_public_key = convert_message(data, 'PublicKey')  # 接收区块链公钥
        data, transfer_time2 = recv_with_header(client_socket)
        server_verify_key = convert_message(data, 'VerifyKey')  # 接收区块链验证公钥

        send_with_header(client_socket, convert_message(client_public_key, 'bytes'))  # 发送网关公钥
        send_with_header(client_socket, convert_message(client_verify_key, 'bytes'))

        exchange_key_end_time = get_timestamp()
        save_key_to_file(server_public_key, 'pk_bc')
        save_key_to_file(server_verify_key, 'pk_sig_bc')

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
