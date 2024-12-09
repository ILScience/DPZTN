from zerotrustnetworkelement.gateway.gw_function import *
from zerotrustnetworkelement.encryption.myhash import *
from zerotrustnetworkelement.function import *


def gw_info_generate():
    ip, client_info = get_network_info()  # 生成网关信息gw_Info
    client_hash_info = hash_encrypt(convert_message(client_info, 'str'))  # 对网关身份信息进行加密
    return client_hash_info

