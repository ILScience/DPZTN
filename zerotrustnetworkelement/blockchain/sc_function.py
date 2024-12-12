# 调用智能合约函数
from zerotrustnetworkelement.blockchain.bc_configure import *


# 查询gid是否注册
def query_gid_state(loop, cli, org, ip, gid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[gid],
        cc_name='ztne',
        fcn='query_gid_state'
    ))
    return response


# 上传网关注册信息
def update_gid_info(loop, cli, org, ip, gid, server_public_key, server_verify_key, client_public_key, client_verify_key,
                    client_hash_info):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[gid, server_public_key, server_verify_key, client_public_key, client_verify_key, client_hash_info],
        cc_name='ztne',
        fcn='update_gid_info'
    ))
    return response


# 更新注册状态
def update_gid_reg_state(loop, cli, org, ip, gid, client_sig_verify_result):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[gid, client_sig_verify_result],
        cc_name='ztne',
        fcn='update_gid_reg_state'
    ))
    return response


# 查询区块链公钥
def query_bc_pk(loop, cli, org, ip, gid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[gid],
        cc_name='ztne',
        fcn='query_bc_pk'
    ))
    return response


# 查询网关公钥
def query_gw_pk(loop, cli, org, ip, gid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[gid],
        cc_name='ztne',
        fcn='query_gw_pk'
    ))
    return response


# 查询区块链认证公钥
def query_bc_sig_pk(loop, cli, org, ip, gid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[gid],
        cc_name='ztne',
        fcn='query_bc_sig_pk'
    ))
    return response


# 查询网关认证公钥
def query_gw_sig_pk(loop, cli, org, ip, gid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[gid],
        cc_name='ztne',
        fcn='query_gw_sig_pk'
    ))
    return response


def query_gw_hash_info(loop, cli, org, ip, gid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[gid],
        cc_name='ztne',
        fcn='query_gw_hash_info'
    ))
    return response


# 更新网关注册状态
def update_gid_auth_state(loop, cli, org, ip, gid, result):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[gid, result],
        cc_name='ztne',
        fcn='update_gid_auth_state'
    ))
    return response


def query_uid_state(loop, cli, org, ip, uid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[uid],
        cc_name='ztne',
        fcn='query_uid_state'
    ))
    return response


def update_uid_info(loop, cli, org, ip, uid, user_hash_info, gateway_public_key, gateway_verify_key, user_pk,
                    user_sig_pk):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[uid, user_hash_info, gateway_public_key, gateway_verify_key, user_pk, user_sig_pk],
        cc_name='ztne',
        fcn='update_uid_info'
    ))
    return response

# 更新注册状态
def update_uid_reg_state(loop, cli, org, ip, uid, client_sig_verify_result):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[uid, client_sig_verify_result],
        cc_name='ztne',
        fcn='update_gid_reg_state'
    ))
    return response


def query_user_hash_info(loop, cli, org, ip, uid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[uid],
        cc_name='ztne',
        fcn='query_user_hash_info'
    ))
    return response


def update_uid_auth_state(loop, cli, org, ip, uid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[uid],
        cc_name='ztne',
        fcn='update_uid_auth_state'
    ))
    return response


# 查询网关公钥
def query_gateway_pk(loop, cli, org, ip, gid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[gid],
        cc_name='ztne',
        fcn='query_gateway_pk'
    ))
    return response
