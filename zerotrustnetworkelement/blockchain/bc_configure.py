import os

net_profile_name = 'network_ztne.json'
net_profile_path = os.path.join(os.path.abspath(''), net_profile_name)

bc_ip = '51.1.1.1'
# bc_ip = '192.168.99.50'
bc_port = 20000
sc_port = 10000

ip_peer_map = {
    '51.1.1.1': 'peer0.org1.example.com',
    '51.1.2.1': 'peer0.org2.example.com',
    '51.1.3.1': 'peer0.org3.example.com'
}
