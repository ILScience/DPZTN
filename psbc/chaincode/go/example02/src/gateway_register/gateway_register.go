package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
)

// SimpleChaincode example simple Chaincode implementation
type SimpleChaincode struct{}

// GWInfo 网关身份信息定义
type GWInfo struct {
	GID            string
	BcPk           string
	BcSigPk        string
	GwPk           string
	GwSigPk        string
	GwHashInfo     string
	GwState        string
	GwRegTimes     int
	GwRegSucTimes  int
	GwRegTS        string
	GwAuthTimes    int
	GwAuthSucTimes int
	GwAuthTS       string
}

// 用户身份信息
type UInfo struct {
	UID            string
	GwPk           string
	GwSigPk        string
	UPk            string
	USigPk         string
	UHashInfo      string
	UState         string
	URegTimes      int
	URegSucTimes   int
	URegTS         string
	UAuthTimes     int
	UAuthSucTimes  int
	UAuthTS        string
	AccessLevel    int
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
	fmt.Println("3.query_bc_pk:[gid]")
	fmt.Println("4.query_gw_pk:[gid]")
	fmt.Println("5.query_gw_hash_info:[gid]")
	fmt.Println("6.update_gid_auth_state")
	fmt.Printf("Authen Chaincode Init Ends at %s\n", getTime())
	return shim.Success([]byte("Authentication Chaincode Initialized at " + getTime()))
}

// 调用链码
func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	function, args := stub.GetFunctionAndParameters()
	switch function {
	case "query_gid":
		return t.query_gid(stub, args)
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
	default:
		return shim.Error("Invalid invoke function name.")
	}
}

//1.查询gid是否注册
func (t *SimpleChaincode) query_gid(stub shim.ChaincodeStubInterface, args []string) pb.Response {
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
		return shim.Success([]byte("False"))
	} else {
		return shim.Error(fmt.Sprintf("gid %s exists", GID))
	}
}

//2. 上传网关注册信息
func (t *SimpleChaincode) register_gid(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// 定义区块链、网关信息和行为信息结构体

	var gateway GWInfo
	var err error

	txid := stub.GetTxID()

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
	if gid != nil {
		return shim.Error(fmt.Sprintf("Register error.User" + args[0] + " already registered!+++" + txid))
	}

	// 如果 GID 不存在，初始化网关和区块链信息
	gateway.GID = args[0]

	gateway.BcPk = args[1]    // 区块链公钥
	gateway.BcSigPk = args[2] // 区块链签名公钥

	gateway.GwPk = args[3]       // 网关公钥
	gateway.GwSigPk = args[4]    // 网关签名公钥
	gateway.GwHashInfo = args[5] // 网关哈希信息

	gateway.GwState = args[6] // 网关ID状态

	gateway.GwRegTimes = 1
	gateway.GwRegSucTimes = 1
	gateway.GwRegTS = getTime()
	gateway.GwAuthTimes = 0
	gateway.GwAuthSucTimes = 0
	gateway.GwAuthTS = "False"

	gatewayJson, err := json.Marshal(gateway)
	if err != nil {
		return shim.Error("Marshal Error")
	}
	err = stub.PutState(gateway.GID, gatewayJson)
	if err != nil {
		return shim.Error("PutState error.")
	}

	ret := string(gatewayJson) + txid
	return shim.Success([]byte(ret))
}

//3.查询gid是否注册
func (t *SimpleChaincode) query_gid_state(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	GID := args[0]
	gidState, err := stub.GetState(GID + ".GwState")
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get gid for gid %s. Error: %s", GID, err))
	}
	if gidState == nil || len(gidState) == 0 {
		return shim.Success([]byte("False"))
	} else if string(gidState) == "10" {
		return shim.Success([]byte("gid " + string(GID) + "registered " + string(gidState)))
	} else if string(gidState) == "11" {
		return shim.Success([]byte("gid " + string(GID) + "registered and authenticated " + string(gidState)))
	} else {
		return shim.Error("Invalid gid state")
	}
}

// 查询网关的区块链公钥 (BcPk)
func (t *SimpleChaincode) query_bc_pk(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// 检查传入的参数数量是否为1（GID）
	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	var err error
	var gateway GWInfo

	// 获取 GID
	gid := args[0]

	// 从区块链中获取网关信息
	gatewayData, err := stub.GetState(gid)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get gateway data for GID %s: %s", gid, err))
	}
	if gatewayData == nil {
		return shim.Error(fmt.Sprintf("No registered for GID %s", gid))
	}

	// 反序列化网关数据
	err = json.Unmarshal(gatewayData, &gateway)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to unmarshal gateway data: %s", err))
	}

	// 返回网关的区块链公钥 (BcPk)
	return shim.Success([]byte(gateway.BcPk))
}

func (t *SimpleChaincode) query_gw_pk(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// 检查传入的参数数量是否为1（GID）
	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	var err error
	var gateway GWInfo

	// 获取 GID
	gid := args[0]

	// 从区块链中获取网关信息
	gatewayData, err := stub.GetState(gid)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get gateway data for GID %s: %s", gid, err))
	}
	if gatewayData == nil {
		return shim.Error(fmt.Sprintf("No registered for GID %s", gid))
	}

	// 反序列化网关数据
	err = json.Unmarshal(gatewayData, &gateway)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to unmarshal gateway data: %s", err))
	}

	// 返回网关的区块链公钥 (BcPk)
	return shim.Success([]byte(gateway.GwPk))
}

func (t *SimpleChaincode) query_gw_hash_info(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// 检查传入的参数数量是否为1（GID）
	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	var err error
	var gateway GWInfo

	// 获取 GID
	gid := args[0]

	// 从区块链中获取网关信息
	gatewayData, err := stub.GetState(gid)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get gateway data for GID %s: %s", gid, err))
	}
	if gatewayData == nil {
		return shim.Error(fmt.Sprintf("No registered for GID %s", gid))
	}

	// 反序列化网关数据
	err = json.Unmarshal(gatewayData, &gateway)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to unmarshal gateway data: %s", err))
	}

	// 返回网关的区块链公钥 (BcPk)
	return shim.Success([]byte(gateway.GwHashInfo))
}

func (t *SimpleChaincode) update_gid_auth_state(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// 检查传入的参数数量是否为1（GID）
	if len(args) != 2 {
		return shim.Error("Incorrect number of arguments. Expecting 2")
	}

	var err error
	var gateway GWInfo

	// 获取 GID
	gid := args[0]
	gidstate := args[1]

	// 从区块链中获取网关信息
	gatewayData, err := stub.GetState(gid)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get gateway data for GID %s: %s", gid, err))
	}
	if gatewayData == nil {
		return shim.Error(fmt.Sprintf("No registered for GID %s", gid))
	}

	// 反序列化网关数据
	err = json.Unmarshal(gatewayData, &gateway)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to unmarshal gateway data: %s", err))
	}
	gateway.GwState = gidstate
	updatedGatewayJson, err := json.Marshal(gateway)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to marshal gateway data: %s", err))
	}
	// 返回更新后的网关信息和交易ID
	ret := string(updatedGatewayJson) + "+++ TransactionID: " + stub.GetTxID()
	return shim.Success([]byte(ret))

}

func (t *SimpleChaincode) query_uid(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	UID := args[0]
	uid, err := stub.GetState(UID)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get uid for uid %s. Error: %s", UID, err))
	}
	if uid == nil || len(uid) == 0 {
		fmt.Printf("uid %s does not exist\n", UID)
		return shim.Success([]byte("False"))
	} else {
		return shim.Error(fmt.Sprintf("uid %s exists", UID))
	}
}

//2. 上传网关注册信息
func (t *SimpleChaincode) register_uid(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// 定义区块链、网关信息和行为信息结构体

	var user UInfo
	var err error

	txid := stub.GetTxID()

	// 检查传入参数数量是否正确，期望接收6个参数
	if len(args) != 7 {
		return shim.Error("Incorrect number of arguments. Expecting 7")
	}

	// 获取指定 GID 的状态信息
	uid, err := stub.GetState(args[0])
	if err != nil {
		// 错误处理：获取链上数据失败
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error("Failed to get state")
	}
	if uid != nil {
		return shim.Error(fmt.Sprintf("Register error.User" + args[0] + " already registered!+++" + txid))
	}

	// 如果 GID 不存在，初始化网关和区块链信息
	user.UID = args[0]

	user.UHashInfo = args[1]
	user.GwPk = args[2]
	user.GwSigPk = args[3]
	user.UPk = args[4]
	user.USigPk = args[5]
	user.UState = args[6]

	user.URegTimes = 1
	user.URegSucTimes = 1
	user.URegTS = getTime()

	user.UAuthTimes = 0
	user.UAuthSucTimes = 0
	user.UAuthTS = "False"

	user.AccessTimes = 0
	user.AccessSucTimes = 0
	user.AccessTS = "False"
	user.AccessLevel = 0

	userJson, err := json.Marshal(user)
	if err != nil {
		return shim.Error("Marshal Error")
	}
	err = stub.PutState(user.UID, userJson)
	if err != nil {
		return shim.Error("PutState error.")
	}

	ret := string(userJson) + txid
	return shim.Success([]byte(ret))
}

//3.查询uid是否注册
func (t *SimpleChaincode) query_uid_state(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	UID := args[0]
	uidState, err := stub.GetState(UID + ".UState")
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get uid for uid %s. Error: %s", UID, err))
	}
	if uidState == nil || len(uidState) == 0 {
		return shim.Success([]byte("False"))
	} else if string(uidState) == "100" {
		return shim.Success([]byte("gid " + string(GID) + "registered " + string(uidState)))
	} else if string(uidState) == "110" {
		return shim.Success([]byte("gid " + string(GID) + "registered and authenticated " + string(uidState)))
	} else {
		return shim.Error("Invalid gid state")
	}
}

func (t *SimpleChaincode) query_uid_hash_info(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// 检查传入的参数数量是否为1（GID）
	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	var err error
	var user UInfo

	// 获取 GID
	uid := args[0]

	// 从区块链中获取网关信息
	userData, err := stub.GetState(uid)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get user data for UID %s: %s", uid, err))
	}
	if userData == nil {
		return shim.Error(fmt.Sprintf("No registered for UID %s", uid))
	}

	// 反序列化网关数据
	err = json.Unmarshal(userData, &user)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to unmarshal user data: %s", err))
	}

	// 返回网关的区块链公钥 (BcPk)
	return shim.Success([]byte(user.UHashInfo))
}

func (t *SimpleChaincode) query_user_pk(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// 检查传入的参数数量是否为1（GID）
	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	var err error
	var user UInfo

	// 获取 GID
	uid := args[0]

	// 从区块链中获取网关信息
	userData, err := stub.GetState(uid)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get user data for UID %s: %s", uid, err))
	}
	if userData == nil {
		return shim.Error(fmt.Sprintf("No registered for UID %s", uid))
	}

	// 反序列化网关数据
	err = json.Unmarshal(userData, &user)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to unmarshal user data: %s", err))
	}

	// 返回网关的区块链公钥 (BcPk)
	return shim.Success([]byte(user.GwPk))
}

func (t *SimpleChaincode) update_uid_auth_state(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// 检查传入的参数数量是否为1（GID）
	if len(args) != 2 {
		return shim.Error("Incorrect number of arguments. Expecting 2")
	}

	var err error
	var user UInfo

	// 获取 GID
	uid := args[0]
	userstate := args[1]

	// 从区块链中获取网关信息
	userData, err := stub.GetState(uid)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get user data for UID %s: %s", uid, err))
	}
	if userData == nil {
		return shim.Error(fmt.Sprintf("No registered for UID %s", uid))
	}

	// 反序列化网关数据
	err = json.Unmarshal(userData, &user)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to unmarshal user data: %s", err))
	}
	user.UState = userstate
	updatedUserJson, err := json.Marshal(user)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to marshal user data: %s", err))
	}
	// 返回更新后的网关信息和交易ID
	ret := string(updatedUserJson) + "+++ TransactionID: " + stub.GetTxID()
	return shim.Success([]byte(ret))

}

func main() {
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		fmt.Printf("\n--------------------------------Error starting Simple chaincode: %s--------------------------------\n", err)
	}
}
