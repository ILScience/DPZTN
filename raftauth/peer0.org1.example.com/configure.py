import psutil
import os


net_profile_name='network_raftauth.json'
net_profile_path=os.path.join(os.path.abspath(''),net_profile_name)


ia_server_port=20000
ac_server_port=30000
sm_register_port = 40000
sm_accessnet_port=40001
sm_corenet_port = 40002
sm_user_port=40003
sm_update_port = 40004
sf_interface_port = 50000


myEID=psutil.net_if_addrs()['eth2'][0].address
myRLOC=psutil.net_if_addrs()['eth1'][0].address
gateway_EID={'51.1.1':'51.1.1.1','51.1.2':'51.1.2.1','51.1.3':'51.1.3.1'}[myEID[:-2]]
all_gateway_RLOC=['50.1.1.1','50.1.2.1','50.1.3.1']
other_gateway_RLOC=[i for i in all_gateway_RLOC if i !=myRLOC ]
all_gateway_EID = ['51.1.1.1', '51.1.2.1', '51.1.3.1']
other_gateway_EID=[i for i in all_gateway_EID if i !=myEID ]


ip_peer_map = {
    '51.1.1.1': 'peer0.org1.example.com',
    '51.1.2.1': 'peer0.org2.example.com',
    '51.1.3.1': 'peer0.org3.example.com'
    }


ip_name_map = {
    '51.1.1.1': 'Gateway.51.1.1.1',
    '51.1.2.1': 'Gateway.51.1.2.1',
    '51.1.3.1': 'Gateway.51.1.3.1'
}
