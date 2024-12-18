# 调用智能合约函数
from zerotrustnetworkelement.blockchain.bc_configure import *


# 1.查询gid是否注册
def query_gid(loop, cli, org, ip, gid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[str(gid)],
        cc_name='ztne',
        fcn='query_gid'
    ))
    print(response)
    return response


# 2.上传网关注册信息
def register_gid(loop, cli, org, ip, gid, bc_pk, bc_sig_pk, gw_pk, gw_sig_pk, gw_hash_info, client_sig_verify_result):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[str(gid), str(bc_pk), str(bc_sig_pk), str(gw_pk), str(gw_sig_pk), str(gw_hash_info),
              str(client_sig_verify_result)],
        cc_name='ztne',
        fcn='register_gid'
    ))
    print(response)
    return response


#######################################################################################################################


# 3.查询gid状态
def query_gid_state(loop, cli, org, ip, gid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[str(gid)],
        cc_name='ztne',
        fcn='query_gid_state'
    ))
    print("gid state is ", response)
    return response


# 4.查询区块链公钥
def query_bc_pk(loop, cli, org, ip, gid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[str(gid)],
        cc_name='ztne',
        fcn='query_bc_pk'
    ))
    print(response)
    return response


# 5.查询网关公钥
def query_gw_pk(loop, cli, org, ip, gid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[str(gid)],
        cc_name='ztne',
        fcn='query_gw_pk'
    ))
    print(response)
    return response


# 6.查询网关身份信息
def query_gw_hash_info(loop, cli, org, ip, gid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[str(gid)],
        cc_name='ztne',
        fcn='query_gw_hash_info'
    ))
    print(response)
    return response


# 7.更新网关认证状态
def update_gid_auth_state(loop, cli, org, ip, gid, gid_auth_verify_result):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[str(gid), str(gid_auth_verify_result)],
        cc_name='ztne',
        fcn='update_gid_auth_state'
    ))
    print(response)
    return response


#######################################################################################################################


# 8.查询uid状态
def query_uid(loop, cli, org, ip, uid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[str(uid)],
        cc_name='ztne',
        fcn='query_uid'
    ))
    print(response)
    return response


# 9.uid注册
def register_uid(loop, cli, org, ip, uid, gid, user_hash_info, gateway_pk, gateway_sig_pk, user_pk, user_sig_pk,
                 user_reg_verify_result):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[str(uid), str(gid), str(user_hash_info), str(gateway_pk), str(gateway_sig_pk), str(user_pk),
              str(user_sig_pk), str(user_reg_verify_result)],
        cc_name='ztne',
        fcn='register_uid'
    ))
    print(response)
    return response


# 8.查询uid状态
def query_uid_state(loop, cli, org, ip, uid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[str(uid)],
        cc_name='ztne',
        fcn='query_uid_state'
    ))
    print(response)
    return response


#######################################################################################################################

# 11.查询用户身份信息
def query_user_hash_info(loop, cli, org, ip, uid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[str(uid)],
        cc_name='ztne',
        fcn='query_user_hash_info'
    ))
    print(response)
    return response


# 12.更新uid认证状态
def update_uid_auth_state(loop, cli, org, ip, uid, auth_result):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[str(uid), str(auth_result)],
        cc_name='ztne',
        fcn='update_uid_auth_state'
    ))
    print(response)
    return response


# 13.查询用户公钥
def query_user_pk(loop, cli, org, ip, uid):
    response = loop.run_until_complete(cli.chaincode_invoke(
        requestor=org,
        channel_name='mychannel',
        peers=[ip_peer_map[ip]],
        args=[str(uid)],
        cc_name='ztne',
        fcn='query_user_pk'
    ))
    print(response)
    return response
