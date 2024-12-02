from zerotrustnetworkelement.gateway.gw_function import *
from zerotrustnetworkelement.encryption.myhash import *
from zerotrustnetworkelement.function import *


def user_info_generate():
    ip, client_info = get_network_info()  # 生成用户属性信息
    client_hash_info = hash_encrypt(convert_message(client_info, 'str'))  # 对网关身份信息进行加密
    user_name = 'ip707'
    user_password = '123456'
    user_info = f'{user_name}||{user_password}'
    user_hash_info = hash_encrypt(user_info)
    uinfo = f'{client_hash_info}||{user_hash_info}'
    return uinfo
