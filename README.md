# DPZTN

DPZTN is an experimental **Data-Plane Zero-Trust Network** prototype that integrates identity authentication, access control, blockchain-based trust management, malicious traffic generation, and programmable data-plane enforcement.

## Project Structure

```text
DPZTN/
├── DT/
│   ├── build/
│   ├── logs/
│   ├── pcaps/
│   ├── Makefile
│   ├── action.txt
│   ├── decision_tree.p4
│   ├── mc.py
│   ├── topology.json
│   └── tree.txt
│
├── chaincode/
│   ├── go/
│   │   └── example02/
│   │       └── src/
│   │           └── ZTNE/
│   └── go.mod
│
├── raftauth/
│   ├── orderer0/
│   ├── orderer1/
│   ├── orderer2/
│   ├── orderer3/
│   ├── orderer4/
│   ├── peer0.org1.example.com/
│   ├── peer0.org2.example.com/
│   ├── peer0.org3.example.com/
│   ├── peer1.org1.example.com/
│   ├── peer1.org2.example.com/
│   ├── peer1.org3.example.com/
│   ├── peer2.org1.example.com/
│   ├── peer2.org2.example.com/
│   ├── peer2.org3.example.com/
│   └── ia_regi.pcap
│
├── request/
│   ├── auth_request_circulate.py
│   ├── auth_request_single.py
│   ├── configure.py
│   ├── ia_user.py
│   └── network_raft_100.json
│
├── sendpkt/
│   ├── malicious_user.py
│   ├── malicious_user_2.py
│   └── normal_user.py
│
├── zerotrustnetworkelement/
│   ├── blockchain/
│   ├── encryption/
│   ├── gateway/
│   ├── user/
│   ├── function.py
│   └── __init__.py
│
└── README.md
```

## Modules

### `DT`

Contains the P4-based decision-tree classification module.

* `decision_tree.p4`: packet parsing and decision-tree rule execution
* `mc.py`: P4Runtime rule installation
* `tree.txt`: decision-tree rules
* `action.txt`: classification actions
* `topology.json`: BMv2 topology configuration
* `build/`: compiled P4 files
* `logs/`: runtime logs
* `pcaps/`: packet captures

### `chaincode`

Contains Hyperledger Fabric chaincode for managing:

* gateway registration and authentication
* user registration and authentication
* identity and public-key information
* user roles and permissions
* trust and risk values
* access and behavior records

### `raftauth`

Contains Hyperledger Fabric node materials and experimental packet captures.

The current structure includes:

* 5 Orderer nodes
* 3 organizations
* 9 Peer nodes

### `request`

Contains scripts for generating registration and authentication requests.

* `auth_request_single.py`: executes a single request
* `auth_request_circulate.py`: repeatedly generates requests
* `ia_user.py`: user identity registration and authentication
* `configure.py`: request-side configuration
* `network_raft_100.json`: Fabric network configuration

### `sendpkt`

Contains normal and malicious traffic generators.

* `normal_user.py`: generates normal user traffic
* `malicious_user.py`: generates malicious traffic and DDoS traffic
* `malicious_user_2.py`: generates additional malicious access behavior

Supported experimental traffic includes:

* network-layer DDoS
* application-layer HTTP flooding
* low-rate DDoS
* DNS reflection traffic
* unauthorized resource access
* random authentication and access requests

### `zerotrustnetworkelement`

Contains the main zero-trust network element implementation.

#### `blockchain`

Handles communication with Hyperledger Fabric.

Main functions include:

* gateway registration
* gateway authentication
* user registration
* user authentication
* resource access verification
* smart-contract invocation

#### `encryption`

Provides cryptographic functions.

* `ecc.py`: elliptic-curve operations
* `ecdh.py`: shared-key generation
* `myhash.py`: hashing functions

#### `gateway`

Implements gateway-side processing.

Main functions include:

* receiving user requests
* verifying user identities
* interacting with the blockchain
* returning authentication and access-control results

#### `user`

Implements user-side registration, authentication, and resource-access procedures.

#### `function.py`

Provides common utility functions, including:

* key storage and loading
* message serialization
* socket message framing
* transmission-time measurement
* JSON result storage
* CPU and memory monitoring
* IP and MAC address collection

## Authentication Workflow

```text
User
  |
  |-- Send authentication request and user ID
  |
  |-- Load user private key and gateway public key
  |
  |-- Generate an ECDH shared key
  |
  |-- Generate identity information hash
  |
  |-- Send encrypted zero-knowledge signature
  |
  |<-- Receive encrypted authentication token
  |
  |-- Generate and send zero-knowledge proof
  |
  |<-- Receive authentication result
```

## Access-Control Workflow

```text
User submits a resource request
          |
          v
Gateway verifies authentication status
          |
          v
Blockchain checks role and permission
          |
          v
Gateway returns allow or deny result
          |
          v
Access behavior is recorded
```

## Data-Plane Workflow

```text
Packet arrival
      |
      v
Protocol parsing
      |
      v
Feature extraction
      |
      v
Decision-tree table matching
      |
      v
Traffic classification
      |
      v
Forwarding or dropping
```

## Requirements

The project was developed for an experimental environment using components such as:

* Python 3
* Hyperledger Fabric
* Go
* Docker
* P4
* BMv2
* P4Runtime

Python dependencies may include:

```bash
pip3 install pynacl noknow netifaces psutil scapy pexpect
```

Additional dependencies may be required depending on the Fabric and P4 environments.

## Configuration

Before running the project, update the following files according to the local environment:

```text
request/network_raft_100.json
request/configure.py
zerotrustnetworkelement/blockchain/bc_configure.py
zerotrustnetworkelement/blockchain/connection.py
zerotrustnetworkelement/gateway/gw_configure.py
DT/topology.json
DT/mc.py
```

Check the following parameters:

* Peer and Orderer addresses
* Fabric channel and chaincode names
* MSP and certificate paths
* gateway IP address and port
* BMv2 and P4Runtime addresses
* host IP and MAC addresses
* user and resource information

## Installation

```bash
git clone https://github.com/ILScience/DPZTN.git
cd DPZTN
pip3 install pynacl noknow netifaces psutil scapy pexpect
```

## Security Notice

This repository is intended for authorized research and testing environments only.

Do not run the malicious traffic scripts against public networks, third-party systems, or infrastructure without explicit authorization.

Remove hard-coded credentials, test keys, certificates, and network addresses before deployment.
