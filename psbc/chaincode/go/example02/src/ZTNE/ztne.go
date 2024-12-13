package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
)

// SimpleChaincode example simple Chaincode implementation
type SimpleChaincode struct{}

type BCInfo struct {
	BcPk    string
	BcSigPk string
}

// GWInfo 网关身份信息定义
type GWInfo struct {
	GID        string
	GwPk       string
	GwSigPk    string
	GwHashInfo string
}

// 用户身份信息
type UInfo struct {
	UID       string
	UPk       string
	USigPk    string
	UHashInfo string
}

// 行为信息
type BehaviorInfo struct {
	IDState        string
	IDRegTimes     int
	IDRegSucTimes  int
	IDRegTS        string
	IDAuthTimes    int
	IDAuthSucTimes int
	IDAuthTS       string
}

type AccessBH struct {
	AccessLevel    string
	AccessTimes    int
	AccessSucTimes int
	AccessTS       string
}

// 获取当前时间字符串
func getTime() string {
	time_stamp := time.Now().Unix() //Unix 将 t 表示为 Unix 时间，即从时间点 January 1, 1970 UTC 到时间点 t 所经过的时间（单位秒）。
	//:=简化语法，不用声明变量类型
	time_stamp += 8 * 60 * 60 // Unix时间戳
	time_unix := time.Unix(time_stamp, 0)
	time_string := time_unix.Format("2006/01/02 15:04:05") //把纳秒转化为时间字符串
	return time_string
}

// 初始化链码
func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	fmt.Printf("Authen Chaincode Init Begins at %s\n", getTime())
	fmt.Println("Available functions:")
	fmt.Println("1.query_gid_state:[gid]")
	fmt.Println("2.register_gid:[gid, bc_pk, bc_sig_pk, gw_pk, gw_sig_pk, gw_hash_info]")
	fmt.Println("3.query_bc_pk[gid]")
	fmt.Println("4.query_gw_pk[gid]")
	fmt.Println("5.query_gw_hash_info[gid]")
	fmt.Println("6.update_gid_auth_state[gid, gid_auth_verify_result]")
	fmt.Println("7.query_uid_state[uid]")
	fmt.Println("8.register_uid[uid, user_hash_info, gateway_pk, gateway_sig_pk, user_pk, user_sig_pk]")
	fmt.Println("9.query_user_hash_info[uid]")
	fmt.Println("10.update_uid_auth_state[uid, auth_result]")
	fmt.Println("11.query_user_pk[uid]")
	fmt.Printf("Authen Chaincode Init Ends at %s\n", getTime())
	return shim.Success([]byte("Authentication Chaincode Initialized at " + getTime()))
}

// 调用链码
func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	function, args := stub.GetFunctionAndParameters()
	switch function {
	case "query_gid_state":
		return t.query_gid_state(stub, args)
	case "register_gid":
		return t.register_gid(stub, args)
	case "query_bc_pk":
		return t.query_bc_pk(stub, args)
	case "query_gw_pk":
		return t.query_gw_pk(stub, args)
	case "query_gw_hash_info":
		return t.query_gw_hash_info(stub, args)
	case "update_gid_auth_state":
		return t.update_gid_auth_state(stub, args)
	case "query_uid_state":
		return t.query_uid_state(stub, args)
	case "register_uid":
		return t.register_uid(stub, args)
	case "query_user_hash_info":
		return t.query_user_hash_info(stub, args)
	case "update_uid_auth_state":
		return t.update_uid_auth_state(stub, args)
	case "query_user_pk":
		return t.query_user_pk(stub, args)
	default:
		return shim.Error("Invalid invoke function name.")
	}
}

//1.查询gid是否注册
func (t *SimpleChaincode) query_gid_state(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	GID := args[0]
	gid, err := stub.GetState(GID)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get gid for gid %s. Error: %s", GID, err))
	}
	if gid == nil || len(gid) == 0 {
		fmt.Printf("gid %s does not exist\n", GID)
		return shim.Success([]byte("00"))
	}

	gidState, err := stub.GetState(GID + ".IDState")
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get register gid for GID %s: %s", GID, err.Error()))
	}
	return shim.Success(gidState)
}

//2. 上传网关注册信息
func (t *SimpleChaincode) register_gid(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// 定义区块链、网关信息和行为信息结构体
	var blockchain BCInfo
	var gateway GWInfo
	var behavior BehaviorInfo
	var err error

	// 检查传入参数数量是否正确，期望接收6个参数
	if len(args) != 7 {
		return shim.Error("Incorrect number of arguments. Expecting 7")
	}

	// 获取指定 GID 的状态信息
	gid, err := stub.GetState(args[0])
	if err != nil {
		// 错误处理：获取链上数据失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error("Failed to get state")
	}

	// 如果指定的 GID 不存在（即返回值为空）
	if gid == nil {
		// 如果 GID 不存在，初始化网关和区块链信息
		gateway.GID = args[0]
		blockchain.BcPk = args[1]    // 区块链公钥
		blockchain.BcSigPk = args[2] // 区块链签名公钥
		gateway.GwPk = args[3]       // 网关公钥
		gateway.GwSigPk = args[4]    // 网关签名公钥
		gateway.GwHashInfo = args[5] // 网关哈希信息
		behavior.IDState = args[6]   // 网关ID状态
		if args[6] == "00" {
			behavior.IDRegTimes = 1
			behavior.IDRegSucTimes = 0
			behavior.IDRegTS = "False"
			behavior.IDAuthTimes = 0
			behavior.IDAuthSucTimes = 0
			behavior.IDAuthTS = "False"
		} else if args[6] == "10" {
			behavior.IDRegTimes = 1
			behavior.IDRegSucTimes = 1
			behavior.IDRegTS = getTime()
			behavior.IDAuthTimes = 0
			behavior.IDAuthSucTimes = 0
			behavior.IDAuthTS = "False"
		} else {
			fmt.Printf("Error State %s", args[6])
		}
		// 打印并说明该 GID 尚未注册
		fmt.Printf("gid %s does not exist", args[0])

	} else {
		// 如果 GID 已存在，获取该 GID 对应的网关状态信息
		gidState, err := stub.GetState(gateway.GID + ".IDState")
		if err != nil {
			// 错误处理：获取链上网关状态失败
			fmt.Printf("get state failed. Error: %s", err)
			return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
		}

		// 如果该 GID 的网关状态不存在
		if gidState == nil {
			// 错误处理：网关状态信息缺失
			fmt.Printf("gid %s does not exist", args[0])
			return shim.Error(fmt.Sprintf("gid %s state error", args[0]))
		} else {
			regtimes, err := stub.GetState(gateway.GID + ".IDRegTimes")
			if err != nil {
				fmt.Printf("get state failed. Error: %s", err)
				return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
			}
			regsuctimes, err := stub.GetState(gateway.GID + ".IDRegSucTimes")
			if err != nil {
				fmt.Printf("get state failed. Error: %s", err)
				return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
			}
			idregts, err := stub.GetState(gateway.GID + "IDRegTS")
			if err != nil {
				fmt.Printf("get state failed. Error: %s", err)
				return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
			}
			if string(gidState) == "00" {
				// 如果网关状态为 "00"（注册失败）
				// 则更新网关信息
				gateway.GID = args[0]
				blockchain.BcPk = args[1]
				blockchain.BcSigPk = args[2]
				gateway.GwPk = args[3]
				gateway.GwSigPk = args[4]
				gateway.GwHashInfo = args[5]
				behavior.IDState = args[6] // 更新网关状态

				if args[6] == "00" {
					behavior.IDRegTimes = regtimes + 1
					behavior.IDRegSucTimes = regsuctimes
					behavior.IDRegTS = string(idregts)
					behavior.IDAuthTimes = 0
					behavior.IDAuthSucTimes = 0
					behavior.IDAuthTS = "False"
				} else if args[6] == "10" {
					behavior.IDRegTimes = regtimes + 1
					behavior.IDRegSucTimes = regsuctimes + 1
					behavior.IDRegTS = getTime()
					behavior.IDAuthTimes = 0
					behavior.IDAuthSucTimes = 0
					behavior.IDAuthTS = "False"
				} else {
					fmt.Printf("Error State %s", args[6])
				}
			} else if string(gidState) == "10" {
				behavior.IDRegTimes = regtimes + 1
				behavior.IDRegSucTimes = regsuctimes
				behavior.IDRegTS = string(idregts)
				behavior.IDAuthTimes = 0
				behavior.IDAuthSucTimes = 0
				behavior.IDAuthTS = "False"
				fmt.Println("gid already register")
			} else if string(gidState) == "11" {
				behavior.IDRegTimes = regtimes + 1
				behavior.IDRegSucTimes = regsuctimes
				behavior.IDRegTS = string(idregts)
				behavior.IDAuthTimes = 0
				behavior.IDAuthSucTimes = 0
				behavior.IDAuthTS = "False"
				fmt.Println("gid already authenticated")
			} else {
				fmt.Printf("Error State %s", gidState)
			}
		}
	}

	// 将区块链公钥保存到链账中
	err = stub.PutState(gateway.GID+".BcPk", []byte(blockchain.BcPk))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("put state failed. Error: %s", err)
		return shim.Error("Failed to put state")
	}

	// 将区块链签名公钥保存到链账中
	err = stub.PutState(gateway.GID+".BcSigPk", []byte(blockchain.BcSigPk))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}

	// 将网关公钥保存到链账中
	err = stub.PutState(gateway.GID+".GwPk", []byte(gateway.GwPk))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}

	// 将网关签名公钥保存到链账中
	err = stub.PutState(gateway.GID+".GwSigPk", []byte(gateway.GwSigPk))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}

	// 将网关哈希信息保存到链账中
	err = stub.PutState(gateway.GID+".GwHashInfo", []byte(gateway.GwHashInfo))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}

	// 将网关ID状态保存到链账中
	err = stub.PutState(gateway.GID+".IDState", []byte(behavior.IDState))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}

	err = stub.PutState(gateway.GID+".IDRegTimes", []byte(strconv.Itoa(behavior.IDRegTimes)))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}

	err = stub.PutState(gateway.GID+".IDRegSucTimes", []byte(strconv.Itoa(behavior.IDRegSucTimes)))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}

	err = stub.PutState(gateway.GID+".IDRegTS", []byte(behavior.IDRegTS))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}

	err = stub.PutState(gateway.GID+".IDAuthTimes", strconv.Itoa(behavior.IDAuthTimes))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}
	err = stub.PutState(gateway.GID+".IDAuthSucTimes", strconv.Itoa(behavior.IDAuthSucTimes))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}
	err = stub.PutState(gateway.GID+".IDAuthTS", []byte(behavior.IDAuthTS))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}

	// 获取当前交易的交易ID
	txid := stub.GetTxID()

	// 生成返回字符串，包含链上存储的状态和交易ID
	ret := string(gid)
	ret = ret + "||" + txid

	// 打印返回内容
	fmt.Println(ret)

	blockchainjson, err := json.Marshal(blockchain)
	if err != nil {
		fmt.Printf("json marshal failed. Error: %s", err)
	}
	gatewayjson, err := json.Marshal(gateway)
	if err != nil {
		fmt.Printf("json marshal failed. Error: %s", err)
	}
	behaviorjson, err := json.Marshal(behavior)
	if err != nil {
		fmt.Printf("json marshal failed. Error: %s", err)
	}
	fmt.Println(string(blockchainjson))
	fmt.Println(string(gatewayjson))
	fmt.Println(string(behaviorjson))

	// 返回成功的响应
	return shim.Success([]byte("True"))
}

//3.查询区块链公钥
func (t *SimpleChaincode) query_bc_pk(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var err error
	if len(args) != 1 {
		fmt.Printf("Incorrect number of arguments. Expecting 1. %s\n", args)
	}
	gid := args[0]
	bcpk, err := stub.GetState(gid + ".BcPk")
	if err != nil {
		fmt.Printf("GetState failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("GetState failed. Error: %s", err))
	}
	if bcpk == nil {
		fmt.Printf("%s does not exist", gid)
		return shim.Error(fmt.Sprintf("%s does not register", gid))
	}
	fmt.Printf("Successful get blockchain public key,the key is %s\n", bcpk)
	return shim.Success(bcpk)
}

//4.查询网关公钥
func (t *SimpleChaincode) query_gw_pk(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var err error
	if len(args) != 1 {
		fmt.Printf("Incorrect number of arguments. Expecting 1. %s\n", args)
	}
	gid := args[0]
	gwpk, err := stub.GetState(gid + ".GwPk")
	if err != nil {
		fmt.Printf("GetState failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("GetState failed. Error: %s", err))
	}
	if gwpk == nil {
		fmt.Printf("%s does not exist", gid)
		return shim.Error(fmt.Sprintf("%s does not register", gid))
	}
	fmt.Printf("Successful get blockchain public key,the key is %s\n", gwpk)
	return shim.Success(gwpk)
}

//5.查询网关身份信息
func (t *SimpleChaincode) query_gw_hash_info(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var err error
	if len(args) != 1 {
		fmt.Printf("Incorrect number of arguments. Expecting 1. %s\n", args)
	}
	gid := args[0]
	gwhashinfo, err := stub.GetState(gid + ".GwHashInfo")
	if err != nil {
		fmt.Printf("GetState failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("GetState failed. Error: %s", err))
	}
	if gwhashinfo == nil {
		fmt.Printf("%s does not exist", gid)
		return shim.Error(fmt.Sprintf("%s does not register", gid))
	}
	fmt.Printf("Successful get blockchain public key,the key is %s\n", gwhashinfo)
	return shim.Success(gwhashinfo)
}

//6.更新网关认证状态
func (t *SimpleChaincode) update_gid_auth_state(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var err error
	var blockchain BCInfo
	var gateway GWInfo
	var behavior BehaviorInfo

	if len(args) != 2 {
		fmt.Printf("Incorrect number of arguments. Expecting 2. %s\n", args)
	}

	gid, err := stub.GetState(args[0])
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get gid %s", gid))
	}
	if gid == nil {
		return shim.Error(fmt.Sprintf("gid hasn't registed yet %s", gid))
	} else {
		gidState, err := stub.GetState(gid + ".IDState")
		if err != nil {
			return shim.Error(fmt.Sprintf("Failed to get gid state %s", gid))
		}
		authtimes, err := stub.GetState(gid + ".IDAuthTimes")
		if err != nil {
			fmt.Printf("get state failed. Error: %s", err)
			return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
		}
		authsuctimes, err := stub.GetState(gid + ".IDAuthSucTimes")
		if err != nil {
			fmt.Printf("get state failed. Error: %s", err)
			return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
		}
		idauthts, err := stub.GetState(gid + "IDAuthTS")
		if err != nil {
			fmt.Printf("get state failed. Error: %s", err)
			return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
		}
		if gidState == nil {
			behavior.IDAuthTimes = authtimes + 1
			behavior.IDAuthSucTimes = authsuctimes
			behavior.IDAuthTS = idauthts
			return shim.Error(fmt.Sprintf("%s does not exist", gid))
		} else {
			if gidState == "00" {
				behavior.IDAuthTimes = authtimes + 1
				behavior.IDAuthSucTimes = authsuctimes
				behavior.IDAuthTS = idauthts
				return shim.Error(fmt.Sprintf("gid hasn't been registered %s", gid))
			} else if gidState == "11" {
				behavior.IDAuthTimes = authtimes + 1
				behavior.IDAuthSucTimes = authsuctimes
				behavior.IDAuthTS = idauthts
				return shim.Error(fmt.Sprintf("gid has already been Authenticated %s", gid))
			} else if gidState == "10" {
				if args[1] == "b\"AUTH_SUCCESS\"" {
					behavior.IDAuthTimes = authtimes + 1
					behavior.IDAuthSucTimes = authsuctimes + 1
					behavior.IDAuthTS = getTime()
					behavior.IDState = "11"
				} else {
					behavior.IDAuthTimes = authtimes + 1
					behavior.IDAuthSucTimes = authsuctimes
					behavior.IDAuthTS = idauthts
					return shim.Error(fmt.Sprintf("gid has already been Authenticated %s", gid))
				}
			} else {
				behavior.IDAuthTimes = authtimes + 1
				behavior.IDAuthSucTimes = authsuctimes
				behavior.IDAuthTS = idauthts
				return shim.Error(fmt.Sprintf("gid has an error state %s", gidState))
			}
		}
	}

	// 将网关ID状态保存到链账中
	err = stub.PutState(gid+".IDState", []byte(behavior.IDState))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}
	err = stub.PutState(gid+".IDAuthTimes", strconv.Itoa(behavior.IDAuthTimes))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}
	err = stub.PutState(gateway.GID+".IDAuthSucTimes", strconv.Itoa(behavior.IDAuthSucTimes))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}
	err = stub.PutState(gateway.GID+".IDAuthTS", []byte(behavior.IDAuthTS))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}

	blockchainjson, err := json.Marshal(blockchain)
	if err != nil {
		fmt.Printf("json marshal failed. Error: %s", err)
	}
	gatewayjson, err := json.Marshal(gateway)
	if err != nil {
		fmt.Printf("json marshal failed. Error: %s", err)
	}
	behaviorjson, err := json.Marshal(behavior)
	if err != nil {
		fmt.Printf("json marshal failed. Error: %s", err)
	}
	fmt.Println(string(blockchainjson))
	fmt.Println(string(gatewayjson))
	fmt.Println(string(behaviorjson))

	return shim.Success([]byte("True"))
}

//7.查询uid状态
func (t *SimpleChaincode) query_uid_state(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	uid, err := stub.GetState(args[0])
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get uid for uid %s", uid))
	}
	if uid == nil || len(uid) == 0 {
		fmt.Printf("uid %s does not exist\n", args[0])
		return shim.Success([]byte("00"))
	}

	uidState, err := stub.GetState(uid + ".IDState")
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get register uid for UID %s: %s", uid, err.Error()))
	}
	return shim.Success(uidState)
}

//8.uid注册
func (t *SimpleChaincode) register_uid(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// 定义区块链、网关信息和行为信息结构体
	var gateway GWInfo
	var user UInfo
	var behavior BehaviorInfo
	var err error

	// 检查传入参数数量是否正确，期望接收6个参数
	if len(args) != 8 {
		return shim.Error("Incorrect number of arguments. Expecting 8")
	}

	// 获取指定 UID 的状态信息
	uid, err := stub.GetState(args[0])
	if err != nil {
		// 错误处理：获取链上数据失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error("Failed to get state")
	}

	// 如果指定的 GID 不存在（即返回值为空）
	if uid == nil || len(uid) == 0 {
		// 如果 GID 不存在，初始化网关和区块链信息
		user.UID = args[0]
		gateway.GID = args[1]
		gateway.GwPk = args[2]     // 区块链公钥
		gateway.GwSigPk = args[3]  // 区块链签名公钥
		user.UPk = args[4]         // 网关公钥
		user.USigPk = args[5]      // 网关签名公钥
		user.UHashInfo = args[6]   // 网关哈希信息
		behavior.IDState = args[7] // 网关ID状态
		if args[7] == "000" {
			behavior.IDRegTimes = 1
			behavior.IDRegSucTimes = 0
			behavior.IDRegTS = "False"
			behavior.IDAuthTimes = 0
			behavior.IDAuthSucTimes = 0
			behavior.IDAuthTS = "False"
		} else if args[7] == "100" {
			behavior.IDRegTimes = 1
			behavior.IDRegSucTimes = 1
			behavior.IDRegTS = getTime()
			behavior.IDAuthTimes = 0
			behavior.IDAuthSucTimes = 0
			behavior.IDAuthTS = "False"
		} else {
			fmt.Printf("Error State %s", args[7])
		}
		// 打印并说明该 GID 尚未注册
		fmt.Printf("uid %s does not exist", args[7])

	} else {
		// 如果 UID 已存在，获取该 UID 对应的用户状态信息
		uidState, err := stub.GetState(uid + ".IDState")
		if err != nil {
			// 错误处理：获取链上网关状态失败
			fmt.Printf("get state failed. Error: %s", err)
			return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
		}

		// 如果该 UID 的网关状态不存在
		if uidState == nil {
			// 错误处理：网关状态信息缺失
			fmt.Printf("uid %s does not exist", args[0])
			return shim.Error(fmt.Sprintf("uid %s state error", args[0]))
		} else {
			regtimes, err := stub.GetState(user.UID + ".IDRegTimes")
			if err != nil {
				fmt.Printf("get state failed. Error: %s", err)
				return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
			}
			regsuctimes, err := stub.GetState(user.UID + ".IDRegSucTimes")
			if err != nil {
				fmt.Printf("get state failed. Error: %s", err)
				return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
			}
			idregts, err := stub.GetState(user.UID + "IDRegTS")
			if err != nil {
				fmt.Printf("get state failed. Error: %s", err)
				return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
			}
			if string(uidState) == "000" {
				// 如果网关状态为 "00"（注册失败）
				// 则更新网关信息
				user.UID = args[0]
				gateway.GID = args[1]
				gateway.GwPk = args[2]
				gateway.GwSigPk = args[3]
				user.UPk = args[4]
				user.USigPk = args[5]
				user.UHashInfo = args[6]
				behavior.IDState = args[7] // 更新网关状态

				if args[7] == "000" {
					behavior.IDRegTimes = regtimes + 1
					behavior.IDRegSucTimes = regsuctimes
					behavior.IDRegTS = string(idregts)
					behavior.IDAuthTimes = 0
					behavior.IDAuthSucTimes = 0
					behavior.IDAuthTS = "False"
				} else if args[7] == "100" {
					behavior.IDRegTimes = regtimes + 1
					behavior.IDRegSucTimes = regsuctimes + 1
					behavior.IDRegTS = getTime()
					behavior.IDAuthTimes = 0
					behavior.IDAuthSucTimes = 0
					behavior.IDAuthTS = "False"
				} else {
					fmt.Printf("Error State %s", args[6])
				}
			} else if string(uidState) == "100" {
				behavior.IDRegTimes = regtimes + 1
				behavior.IDRegSucTimes = regsuctimes
				behavior.IDRegTS = string(idregts)
				behavior.IDAuthTimes = 0
				behavior.IDAuthSucTimes = 0
				behavior.IDAuthTS = "False"
				fmt.Println("uid already register")
			} else if string(uidState) == "110" {
				behavior.IDRegTimes = regtimes + 1
				behavior.IDRegSucTimes = regsuctimes
				behavior.IDRegTS = string(idregts)
				behavior.IDAuthTimes = 0
				behavior.IDAuthSucTimes = 0
				behavior.IDAuthTS = "False"
				fmt.Println("uid already authenticated")
			} else {
				fmt.Printf("Error State %s", uidState)
			}
		}
	}

	// 将区块链公钥保存到链账中
	err = stub.PutState(user.UID+".GwPk", []byte(gateway.GwPk))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("put state failed. Error: %s", err)
		return shim.Error("Failed to put state")
	}

	// 将区块链签名公钥保存到链账中
	err = stub.PutState(user.UID+".GwSigPk", []byte(gateway.GwSigPk))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}
	err = stub.PutState(user.UID+".gid", []byte(gateway.GID))
	if err != nil {
		fmt.Printf("put state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to put state. Error: %s", err))
	}

	// 将网关公钥保存到链账中
	err = stub.PutState(user.UID+".UPk", []byte(user.UPk))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}

	// 将网关签名公钥保存到链账中
	err = stub.PutState(user.UID+".USigPk", []byte(user.USigPk))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}

	// 将网关哈希信息保存到链账中
	err = stub.PutState(user.UID+".UHashInfo", []byte(user.UHashInfo))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}

	// 将网关ID状态保存到链账中
	err = stub.PutState(user.UID+".IDState", []byte(behavior.IDState))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}

	err = stub.PutState(user.UID+".IDRegTimes", []byte(strconv.Itoa(behavior.IDRegTimes)))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}

	err = stub.PutState(user.UID+".IDRegSucTimes", []byte(strconv.Itoa(behavior.IDRegSucTimes)))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}

	err = stub.PutState(user.UID+".IDRegTS", []byte(behavior.IDRegTS))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}

	err = stub.PutState(user.UID+".IDAuthTimes", strconv.Itoa(behavior.IDAuthTimes))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}
	err = stub.PutState(user.UID+".IDAuthSucTimes", strconv.Itoa(behavior.IDAuthSucTimes))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}
	err = stub.PutState(user.UID+".IDAuthTS", []byte(behavior.IDAuthTS))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}

	// 获取当前交易的交易ID
	txid := stub.GetTxID()

	// 生成返回字符串，包含链上存储的状态和交易ID
	ret := string(uid)
	ret = ret + "||" + txid

	// 打印返回内容
	fmt.Println(ret)

	gatewayjson, err := json.Marshal(gateway)
	if err != nil {
		fmt.Printf("json marshal failed. Error: %s", err)
	}
	userjson, err := json.Marshal(user)
	if err != nil {
		fmt.Printf("json marshal failed. Error: %s", err)
	}
	behaviorjson, err := json.Marshal(behavior)
	if err != nil {
		fmt.Printf("json marshal failed. Error: %s", err)
	}
	fmt.Println(string(gatewayjson))
	fmt.Println(string(userjson))
	fmt.Println(string(behaviorjson))
	return shim.Success("True")
}

//9.查询用户身份信息
func (t *SimpleChaincode) query_user_hash_info(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var err error
	if len(args) != 1 {
		fmt.Printf("Incorrect number of arguments. Expecting 1. %s\n", args)
	}
	uid := args[0]
	userhashinfo, err := stub.GetState(uid + ".UHashInfo")
	if err != nil {
		fmt.Printf("GetState failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("GetState failed. Error: %s", err))
	}
	if userhashinfo == nil {
		fmt.Printf("%s does not exist", uid)
		return shim.Error(fmt.Sprintf("%s does not register", uid))
	}
	fmt.Printf("Successful get blockchain public key,the key is %s\n", userhashinfo)
	return shim.Success(userhashinfo)
}

//10.更新uid认证状态
func (t *SimpleChaincode) update_uid_auth_state(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var err error
	var gateway GWInfo
	var user UInfo
	var behavior BehaviorInfo

	if len(args) != 2 {
		fmt.Printf("Incorrect number of arguments. Expecting 2. %s\n", args)
	}

	uid, err := stub.GetState(args[0])
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get uid %s", uid))
	}
	if uid == nil {
		return shim.Error(fmt.Sprintf("uid hasn't registed yet %s", uid))
	} else {
		uidState, err := stub.GetState(uid + ".IDState")
		if err != nil {
			return shim.Error(fmt.Sprintf("Failed to get uid state %s", uid))
		}
		authtimes, err := stub.GetState(uid + ".IDAuthTimes")
		if err != nil {
			fmt.Printf("get state failed. Error: %s", err)
			return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
		}
		authsuctimes, err := stub.GetState(uid + ".IDAuthSucTimes")
		if err != nil {
			fmt.Printf("get state failed. Error: %s", err)
			return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
		}
		idauthts, err := stub.GetState(uid + "IDAuthTS")
		if err != nil {
			fmt.Printf("get state failed. Error: %s", err)
			return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
		}
		if uidState == nil {
			behavior.IDAuthTimes = authtimes + 1
			behavior.IDAuthSucTimes = authsuctimes
			behavior.IDAuthTS = idauthts
			return shim.Error(fmt.Sprintf("%s does not exist", uid))
		} else {
			if uidState == "000" {
				behavior.IDAuthTimes = authtimes + 1
				behavior.IDAuthSucTimes = authsuctimes
				behavior.IDAuthTS = idauthts
				return shim.Error(fmt.Sprintf("uid hasn't been registered %s", uid))
			} else if uidState == "110" {
				behavior.IDAuthTimes = authtimes + 1
				behavior.IDAuthSucTimes = authsuctimes
				behavior.IDAuthTS = idauthts
				return shim.Error(fmt.Sprintf("uid has already been Authenticated %s", uid))
			} else if uidState == "100" {
				if args[1] == "b\"AUTH_SUCCESS\"" {
					behavior.IDAuthTimes = authtimes + 1
					behavior.IDAuthSucTimes = authsuctimes + 1
					behavior.IDAuthTS = getTime()
					behavior.IDState = "110"
				} else {
					behavior.IDAuthTimes = authtimes + 1
					behavior.IDAuthSucTimes = authsuctimes
					behavior.IDAuthTS = idauthts
					return shim.Error(fmt.Sprintf("uid has already been Authenticated %s", uid))
				}
			} else {
				behavior.IDAuthTimes = authtimes + 1
				behavior.IDAuthSucTimes = authsuctimes
				behavior.IDAuthTS = idauthts
				return shim.Error(fmt.Sprintf("uid has an error state %s", uidState))
			}
		}
	}

	// 将网关ID状态保存到链账中
	err = stub.PutState(uid+".IDState", []byte(behavior.IDState))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}
	err = stub.PutState(uid+".IDAuthTimes", strconv.Itoa(behavior.IDAuthTimes))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}
	err = stub.PutState(gateway.GID+".IDAuthSucTimes", strconv.Itoa(behavior.IDAuthSucTimes))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}
	err = stub.PutState(gateway.GID+".IDAuthTS", []byte(behavior.IDAuthTS))
	if err != nil {
		// 错误处理：存储失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("Failed to get state. Error: %s", err))
	}

	gatewayjson, err := json.Marshal(gateway)
	if err != nil {
		fmt.Printf("json marshal failed. Error: %s", err)
	}
	userjson, err := json.Marshal(user)
	if err != nil {
		fmt.Printf("json marshal failed. Error: %s", err)
	}
	behaviorjson, err := json.Marshal(behavior)
	if err != nil {
		fmt.Printf("json marshal failed. Error: %s", err)
	}
	fmt.Println(string(gatewayjson))
	fmt.Println(string(userjson))
	fmt.Println(string(behaviorjson))

	return shim.Success([]byte("True"))
}

//11.查询网关公钥
func (t *SimpleChaincode) query_user_pk(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var err error
	if len(args) != 1 {
		fmt.Printf("Incorrect number of arguments. Expecting 1. %s\n", args)
	}
	uid := args[0]
	userpk, err := stub.GetState(uid + ".UPk")
	if err != nil {
		fmt.Printf("GetState failed. Error: %s", err)
		return shim.Error(fmt.Sprintf("GetState failed. Error: %s", err))
	}
	if userpk == nil {
		fmt.Printf("%s does not exist", uid)
		return shim.Error(fmt.Sprintf("%s does not register", uid))
	}
	fmt.Printf("Successful get blockchain public key,the key is %s\n", userpk)
	return shim.Success(userpk)
}

// 链码主入口
func main() {
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		fmt.Printf("\n-----------------Error starting Simple chaincode: %s--------------------\n", err)
	}
}
