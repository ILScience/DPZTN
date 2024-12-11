import asyncio
from hfc.fabric import Client


# 连接到智能合约
def sc_connection(net_profile_path, org):
    cli = Client(net_profile=net_profile_path)
    cli.new_channel('mychannel')
    loop = asyncio.get_event_loop()
    org_admin = cli.get_user(org, 'Admin')
    print('blockchain connection successful!')
    return loop, cli, org_admin
