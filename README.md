# DPZTN
Zero-Trust Network Element
A prototype implementation of a zero-trust network element that integrates identity authentication, access control, blockchain-based trust management, and P4 programmable data-plane detection.
Features
Gateway and user registration
Zero-knowledge identity authentication
Role- and privilege-based resource access control
Hyperledger Fabric-based identity and trust management
P4 decision-tree traffic classification
Normal-user and malicious-user traffic simulation
Support for DDoS, low-rate DDoS, DNS reflection, unauthorized access, and sensitive-resource access scenarios
System Architecture
The system consists of four main parts:
User side  
Handles user registration, authentication, resource requests, and traffic generation.
Zero-trust gateway  
Acts as a secure proxy between users and the blockchain network. It verifies identities, enforces access-control decisions, and protects control messages.
Blockchain network  
Stores gateway and user identities, authentication states, public keys, trust values, risk values, and access permissions.
Programmable data plane  
Uses a P4 decision-tree classifier and P4Runtime control program to classify and forward traffic in BMv2.
Main Modules
```text
.
├── raftauth/                  # Hyperledger Fabric network configuration
├── normal\_user.py            # Normal user behavior simulation
├── malicious\_user.py         # Malicious traffic and attack simulation
├── malicious\_user\_2.py       # Token-based malicious behavior simulation
├── auth\_request\_circulate.py # Batch registration/authentication requests
├── auth\_request\_single.py    # Command-line entry for individual functions
├── configure.py              # Common runtime configuration
├── ia\_user.py                # User-side identity authentication
├── ecc.py                    # Curve25519 encryption and Ed25519 signatures
├── ecdh.py                   # Secure session establishment
├── myhash.py                 # SHA-256 identity hashing
├── decision\_tree.p4          # P4 decision-tree classifier
├── mc.py                     # P4Runtime control program
├── topology.json             # BMv2 experiment topology
├── sc\_function.py            # Smart-contract invocation interface
├── connection.py             # Hyperledger Fabric connection helper
└── ztne.go                   # Core chaincode
```
Environment
Component	Version
Hyperledger Fabric	1.4.3
Docker	26.1.3
Go	1.10.3
The Fabric test network contains three organizations, nine peer nodes, and five orderer nodes.
Core Workflow
```text
Gateway registration
        ↓
Gateway authentication
        ↓
User registration
        ↓
User authentication
        ↓
Access-control request
        ↓
Blockchain verification
        ↓
Resource delivery / traffic enforcement
```
Cryptographic protection is provided through Curve25519, Ed25519, SHA-256, secure session establishment, and zero-knowledge proofs.
Data-Plane Detection
The P4 module parses Ethernet, IPv4, and TCP headers, applies a decision-tree classifier, writes the result to packet metadata, and forwards or drops packets according to P4Runtime-installed rules.
The default experiment topology contains one BMv2 switch and four hosts.
Smart Contract
The `ztne.go` chaincode manages:
Gateway registration and authentication
User registration and authentication
Public keys and identity hashes
Registration and authentication states
Trust, risk, and behavior scores
Role- and privilege-based resource access
Notes
Update all IP addresses, ports, certificate paths, key paths, and Fabric connection profiles before deployment.
The repository is intended for research and experimental validation.
Do not use the default configuration in a production environment.
