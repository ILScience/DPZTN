import netifaces


# 获取网关ip、MAC地址
def get_network_info():
    interfaces = netifaces.interfaces()
    network_info = {}
    ip = None

    for interface in interfaces:
        addresses = netifaces.ifaddresses(interface)

        # 检查是否有 IPv4 地址
        if netifaces.AF_INET in addresses:
            ip = addresses[netifaces.AF_INET][0]['addr']
            network_info['IP 地址'] = ip

        # 检查是否有 MAC 地址
        if netifaces.AF_LINK in addresses:
            mac_address = addresses[netifaces.AF_LINK][0]['addr']
            network_info['MAC 地址'] = mac_address

    return ip, network_info
