# 调用智能合约函数
from zerotrustnetworkelement.blockchain.bc_configure import *
from zerotrustnetworkelement.function import *


# 上传网关注册信息
def update_gw_info(loop, cli, org, ip, hash_info, gid, gw_pk, gw_pk_sig, reg_result, bc_pk, bc_pk_sig):
    print(gw_pk)
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[hash_info, gid, gw_pk, gw_pk_sig, reg_result, bc_pk, bc_pk_sig],
        cc_name='ztne',
        fcn='update_gw_info'
    ))
    if response is True:
        format_and_print(f'Gateway information uploaded successfully', '-', 'center')
    else:
        format_and_print(f'Gateway information upload failure:{response}', chr(0x00D7), 'left')
    return response


def query_register_state(loop, cli, org, ip, gid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[gid],
        cc_name='ztne',
        fcn='query_register_state'
    ))
    format_and_print('Gateway already register！', '-', 'center')
    return response


def query_auth_state(loop, cli, org, ip, gid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[gid],
        cc_name='ztne',
        fcn='query_auth_state'
    ))
    format_and_print('Gateway already register！', '-', 'center')
    return response


def query_gid_pubkey(loop, cli, org, ip, gid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[gid],
        cc_name='ztne',
        fcn='query_gid_pubkey'
    ))
    format_and_print('Gateway public key query successful！', '-', 'center')
    return response


def query_gid_verkey(loop, cli, org, ip, gid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[gid],
        cc_name='ztne',
        fcn='query_gid_verkey'
    ))
    format_and_print('Gateway fy key query successful！', '-', 'center')
    return response


def query_bc_pubkey(loop, cli, org, ip, gid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[gid],
        cc_name='ztne',
        fcn='query_bc_pubkey'
    ))
    format_and_print('BlockChain public key query successful！', '-', 'center')
    return response


def query_bc_verkey(loop, cli, org, ip, gid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[gid],
        cc_name='ztne',
        fcn='query_bc_verkey'
    ))
    format_and_print('BlockChain verify key query successful！', '-', 'center')
    return response


def query_gid_hashinfo(loop, cli, org, ip, gid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[gid],
        cc_name='ztne',
        fcn='gid_hashinfo'
    ))
    format_and_print('Gateway encrypted identity information query successful！', '-', 'center')
    return response
