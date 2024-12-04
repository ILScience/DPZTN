from zerotrustnetworkelement.gateway.gw_function import *
from zerotrustnetworkelement.encryption.myhash import *
from zerotrustnetworkelement.function import *


def user_info_generate():
    ip, client_info = get_network_info()  # 生成用户属性信息
    user_name = 'ip707'
    user_password = '123456'
    user_info = f'{client_info}||{user_name}||{user_password}'
    user_hash_info = hash_encrypt(user_info)
    return user_hash_info
