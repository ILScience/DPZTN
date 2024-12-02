from zerotrustnetworkelement.encryption.ecc import *
from zerotrustnetworkelement.function import *


def gw_user_key():
    ecc = ECC()
    if os.path.exists("../../experimentation/gw/sk_gateway.key") and os.path.exists(
            "../../experimentation/gw/pk_gateway.pub"):
        private_key = load_key_from_file("sk_gateway")
        public_key = load_key_from_file('pk_gateway')
    else:
        private_key, public_key = ecc.ecc_genkey()
        save_key_to_file(private_key, "sk_gateway")
        save_key_to_file(public_key, 'pk_gateway')

    if os.path.exists("../../experimentation/gw/sk_sig_gateway.key") and os.path.exists(
            "../../experimentation/gw/pk_sig_gateway.pub"):
        signing_key = load_key_from_file("sk_sig_gateway")
        verify_key = load_key_from_file('pk_sig_gateway')
    else:
        signing_key, verify_key = ecc.ecc_genkey_sign()
        save_key_to_file(signing_key, "sk_sig_gateway")
        save_key_to_file(verify_key, 'pk_sig_gateway')
    return private_key, public_key, signing_key, verify_key, ecc


# 公钥交换
def pk_exchange(client_socket, server_public_key, server_verify_key):
    format_and_print('1.Exchanging Key', ':', 'left')
    try:
        exchange_key_start_time = get_timestamp()

        send_with_header(client_socket, convert_message(server_public_key, 'bytes'))  # 发送区块链公钥
        send_with_header(client_socket, convert_message(server_verify_key, 'bytes'))  # 发送区块链认证密钥

        data, transfer_time1 = recv_with_header(client_socket)
        gateway_public_key = convert_message(data, 'PublicKey')  # 接收网关公钥
        data, transfer_time2 = recv_with_header(client_socket)
        gateway_verify_key = convert_message(data, 'VerifyKey')  # 接收网关认证密钥

        exchange_key_end_time = get_timestamp()
        save_key_to_file(gateway_public_key, 'pk_user')
        save_key_to_file(gateway_verify_key, 'pk_sig_user')
        format_and_print('1.Key exchange successful', '=', 'center')
        exchange_key_duration = exchange_key_end_time - exchange_key_start_time
        return transfer_time1, transfer_time2, exchange_key_duration
    except ConnectionError as conn_err:
        format_and_print(f"Connection error during key exchange: {conn_err}", chr(0x00D7), 'left')
    except ValueError as val_err:
        format_and_print(f"Value error during key exchange: {val_err}", chr(0x00D7), 'left')
    except IOError as io_err:
        format_and_print(f"File I/O error during key exchange: {io_err}", chr(0x00D7), 'left')
    except Exception as e:
        format_and_print(f"An unexpected error occurred during key exchange: {e}", chr(0x00D7), 'left')
