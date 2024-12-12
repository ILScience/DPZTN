# 调用智能合约函数
from zerotrustnetworkelement.blockchain.bc_configure import *


# 1.查询gid是否注册
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


# 2.上传网关注册信息
def register_gid(loop, cli, org, ip, gid, bc_pk, bc_sig_pk, gw_pk, gw_sig_pk, gw_hash_info):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[gid, bc_pk, bc_sig_pk, gw_pk, gw_sig_pk, gw_hash_info],
        cc_name='ztne',
        fcn='register_gid'
    ))
    return response


# 3.更新注册状态
def update_gid_reg_state(loop, cli, org, ip, gid, gw_verify_result):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[gid, gw_verify_result],
        cc_name='ztne',
        fcn='update_gid_reg_state'
    ))
    return response


# 4.查询区块链公钥
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


# 5.查询网关公钥
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


# 6.查询网关身份信息
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


# 7.更新网关注册状态
def update_gid_auth_state(loop, cli, org, ip, gid, gid_auth_verify_result):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[gid, gid_auth_verify_result],
        cc_name='ztne',
        fcn='update_gid_auth_state'
    ))
    return response


# 8.查询uid状态
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


# 9.uid注册
def register_uid(loop, cli, org, ip, uid, user_hash_info, gateway_pk, gateway_sig_pk, user_pk, user_sig_pk):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[uid, user_hash_info, gateway_pk, gateway_sig_pk, user_pk, user_sig_pk],
        cc_name='ztne',
        fcn='register_uid'
    ))
    return response


# 10.更新注册状态
def update_uid_reg_state(loop, cli, org, ip, uid, user_reg_verify_result):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[uid, user_reg_verify_result],
        cc_name='ztne',
        fcn='update_gid_reg_state'
    ))
    return response


# 11.查询用户身份信息
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


# 12.更新uid认证状态
def update_uid_auth_state(loop, cli, org, ip, uid, auth_result):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[uid, auth_result],
        cc_name='ztne',
        fcn='update_uid_auth_state'
    ))
    return response


# 13.查询网关公钥
def query_gateway_pk(loop, cli, org, ip, uid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[uid],
        cc_name='ztne',
        fcn='query_gateway_pk'
    ))
    return response
