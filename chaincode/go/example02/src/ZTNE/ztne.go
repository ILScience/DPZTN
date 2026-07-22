package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
)

// SimpleChaincode example simple Chaincode implementation
type SimpleChaincode struct{}

// GWInfo 网关身份信息定义
type GWInfo struct {
	GID                string
	BcPk               string
	BcSigPk            string
	GwPk               string
	GwSigPk            string
	GwHashInfo         string
	GwState            string
	GwRegTimes         int
	GwRegSucTimes      int
	GwRegTS            string
	GwAuthTimes        int
	GwAuthSucTimes     int
	GwAuthTS           string
	UAuthTimes         int
	UAuthSucTimes      int
	UserAccessTimes    int
	UserAccessSucTimes int
	AccessUserNumber   int
	GReputation        float64
	GRisk              float64
	FL                 float64
}

// 用户身份信息
type UInfo struct {
	UID            string
	GID            string
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
	AccessTimes    int
	AccessSucTimes int
	LegalAccTimes  int
	AccessTS       string

	UserRole          string
	UserLevel         int
	UserMaliciousness float64
	UserPrivilege     int
	UserReputation    float64
	UserRisk          float64
	UserBHScore       float64
}

type User struct {
	ASF           float64
	AC            float64
	ACC           float64
	ACSF          float64
	LAC           float64
	CAPL          float64
	ACF           float64
	HBHS          float64
	HBHR          float64
	behaviorScore float64
	CARL          float64
	SACF          float64
	MTP           float64
}

type Gateway struct {
	GASF    float64
	GAC     float64
	GACSF   float64
	GACC    float64
	UserNum float64
	GRV     float64
	GRR     float64
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

func parseTimeToUnix(timeString string) int64 {
	// 解析时间字符串为 time.Time 类型
	t, err := time.Parse("2006/01/02 15:04:05", timeString)
	if err != nil {
		fmt.Println("Error parsing time:", err)
		return 0
	}
	// 返回对应的 Unix 时间戳（单位秒）
	return t.Unix()
}

// 初始化链码
func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	fmt.Printf("Authen Chaincode Init Begins at %s\n", getTime())
	fmt.Println("Available functions:")
	fmt.Println("1.query_gid:[gid]")
	fmt.Println("2.register_gid:[gid, bc_pk, bc_sig_pk, gw_pk, gw_sig_pk, gw_hash_info]")
	fmt.Println("3.query_gid_state:[gid]")
	fmt.Println("4.query_bc_pk:[gid]")
	fmt.Println("5.query_gw_pk:[gid]")
	fmt.Println("6.query_gw_hash_info:[gid]")
	fmt.Println("7.update_gid_auth_state[gid]")
	fmt.Println("8.query_uid[uid]")
	fmt.Println("9.register_uid[uid, gid, user_hash_info, gateway_pk, gateway_sig_pk, user_pk, user_sig_pk,user_reg_verify_result]")
	fmt.Println("10.query_uid_state[uid]")
	fmt.Println("11.query_uid_hash_info[uid]")
	fmt.Println("12.query_user_pk[uid]")
	fmt.Println("13.update_uid_auth_state[uid]")
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
	case "query_gid_state":
		return t.query_gid_state(stub, args)
	case "query_bc_pk":
		return t.query_bc_pk(stub, args)
	case "query_gw_pk":
		return t.query_gw_pk(stub, args)
	case "query_gw_hash_info":
		return t.query_gw_hash_info(stub, args)
	case "update_gid_auth_state":
		return t.update_gid_auth_state(stub, args)
	case "query_uid":
		return t.query_uid(stub, args)
	case "register_uid":
		return t.register_uid(stub, args)
	case "query_uid_state":
		return t.query_uid_state(stub, args)
	case "query_uid_hash_info":
		return t.query_uid_hash_info(stub, args)
	case "query_user_pk":
		return t.query_user_pk(stub, args)
	case "update_user_auth_state":
		return t.update_uid_auth_state(stub, args)

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
	var err error
	var gateway GWInfo

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

	gidState := gateway.GwState

	if len(gidState) == 0 {
		return shim.Success([]byte("False"))
	} else if gidState == "10" {
		return shim.Success([]byte("gid " + gid + "registered " + gidState))
	} else if gidState == "11" {
		return shim.Success([]byte("gid " + gid + "registered and authenticated " + gidState))
	} else {
		return shim.Error("Invalid gid state")
	}
}

//4.查询网关的区块链公钥 (BcPk)
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

//5.查询网关公钥
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

//6.查询网关身份信息
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

//7.上传网关认证结果
func (t *SimpleChaincode) update_gid_auth_state(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// 检查传入的参数数量是否为1（GID）
	if len(args) != 2 {
		return shim.Error("Incorrect number of arguments. Expecting 2")
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
	gateway.GwState = args[1]
	gateway.GwAuthTS = getTime()
	gateway.GwAuthTimes = 1
	gateway.GwAuthSucTimes = 1
	gateway.GReputation = 100
	gateway.GRisk = 0
	gateway.AccessUserNumber = 0

	gatewayJson, err := json.Marshal(gateway)
	if err != nil {
		return shim.Error("Marshal Error")
	}

	err = stub.PutState(gateway.GID, gatewayJson)
	if err != nil {
		return shim.Error("PutState error.")
	}

	// 返回更新后的网关信息和交易ID
	ret := string(gatewayJson) + "+++ TransactionID: " + stub.GetTxID()
	return shim.Success([]byte(ret))

}

//8.查询uid
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

//9. 上传用户注册信息
func (t *SimpleChaincode) register_uid(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// 定义区块链、网关信息和行为信息结构体

	var user UInfo
	var err error

	txid := stub.GetTxID()

	// 检查传入参数数量是否正确，期望接收6个参数
	if len(args) != 8 {
		return shim.Error("Incorrect number of arguments. Expecting 8")
	}

	// 获取指定 GID 的状态信息
	uid, err := stub.GetState(args[0])
	if err != nil {
		// 错误处理：获取链上数据失败
		return shim.Error("Failed to get state")
	}
	if uid != nil {
		return shim.Error(fmt.Sprintf("Register error.User" + args[0] + " already registered!+++" + txid))
	}

	// 如果 UID 不存在，初始化网关和区块链信息
	user.UID = args[0]
	user.GID = args[1]
	user.UHashInfo = args[2]
	user.GwPk = args[3]
	user.GwSigPk = args[4]
	user.UPk = args[5]
	user.USigPk = args[6]
	user.UState = args[7]

	user.URegTimes = 1
	user.URegSucTimes = 1
	user.URegTS = getTime()

	user.UAuthTimes = 0
	user.UAuthSucTimes = 0
	user.UAuthTS = "False"

	user.AccessTimes = 0
	user.AccessSucTimes = 0
	user.AccessTS = "False"

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

//10.查询uid状态
func (t *SimpleChaincode) query_uid_state(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}
	var user UInfo
	var err error

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
		return shim.Error(fmt.Sprintf("Failed to unmarshal gateway data: %s", err))
	}

	uidState := user.UState

	if len(uidState) == 0 {
		return shim.Success([]byte("False"))
	} else if string(uidState) == "100" {
		return shim.Success([]byte("uid " + string(uid) + "registered " + string(uidState)))
	} else if string(uidState) == "110" {
		return shim.Success([]byte("uid " + string(uid) + "registered and authenticated " + string(uidState)))
	} else {
		return shim.Error("Invalid uid state")
	}
}

//11.查询uid信息
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

//12.查询用户公钥
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

	// 返回网关的区块链公钥 (UPk)
	return shim.Success([]byte(user.UPk))
}

//13.上传用户认证状态
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
	user.UAuthTimes = 1
	user.UAuthSucTimes = 1
	user.UAuthTS = getTime()

	userJson, err := json.Marshal(user)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to marshal user data: %s", err))
	}
	err = stub.PutState(user.UID, userJson)
	if err != nil {
		return shim.Error("PutState error.")
	}
	ret := string(userJson) + "+++ TransactionID: " + stub.GetTxID()
	return shim.Success([]byte(ret))

}

//14.查询用户资源
func (t *SimpleChaincode) update_user_mark(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	if len(args) != 3 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	var err error
	var user UInfo
	var gateway GWInfo

	// 获取 GID
	uid := args[0]
	userRole := args[1]
	queryResource := strconv.Atoi(args[2])

	userData, err := stub.GetState(uid)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get user data for UID %s: %s", uid, err))
	}
	if userData == nil {
		return shim.Error(fmt.Sprintf("No registered for UID %s", uid))
	}
	err = json.Unmarshal(userData, &user)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to unmarshal user data: %s", err))
	}

	gatewayData, err := stub.GetState(user.GID)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get gateway data for UID %s: %s", uid, err))
	}
	if gatewayData == nil {
		return shim.Error(fmt.Sprintf("No registered for UID %s", uid))
	}
	err = json.Unmarshal(gatewayData, &gateway)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to unmarshal gateway data: %s", err))
	}

	if user.UserRole == "" {
		user.UserRole = userRole
		if user.UserRole == "Regular User" {
			user.UserPrivilege = 0
			user.UserLevel = 5
		} else if user.UserRole == "Premium User" {
			user.UserPrivilege = 10
			user.UserLevel = 5
		} else if user.UserRole == "Administrator" {
			user.UserPrivilege = 20
			user.UserLevel = 5
		} else {
			return shim.Error("Invalid user role.")
		}
	} else if user.UserRole != userRole {
		return shim.Error("User role mismatch")
	}
	//计算网关连接的用户数量，判断用户是否是新连接的
	if user.UserRole == "" {
		gateway.AccessUserNumber = gateway.AccessUserNumber + 1
		//计算用户信誉值
		pf := gateway.GReputation / 100
		pas := (gateway.UAuthSucTimes / gateway.GwAuthTimes) * (user.UAuthSucTimes / user.AccessSucTimes)
		pacs := (gateway.UserAccessSucTimes / gateway.UserAccessTimes) * (user.AccessSucTimes / user.AccessTimes)
		plaf := user.LegalAccTimes / user.AccessTimes
		var frl float64
		if queryResource > 30 || queryResource < 0 {
			return shim.Error("No resources")
		} else if queryResource > (user.UserPrivilege + user.UserLevel) {
			frl = 1
		} else {
			frl = math.Floor(float64(1 - ((queryResource - user.UserPrivilege + user.UserLevel) / queryResource)))
		}
		pb := math.Pow(float64(pas), 2) * math.Pow(float64(pacs), 3) * math.Pow(float64(plaf), 2) * math.Pow(frl, 3)
		px := float64(gateway.UAuthSucTimes/gateway.GwAuthTimes) * float64(gateway.UserAccessSucTimes/gateway.UserAccessTimes) * ((float64(gateway.AccessUserNumber-1)*gateway.FL + frl) / float64(gateway.AccessUserNumber))
		user.UserReputation = pb * pf / px
		//计算用户风险值
		pff := gateway.GRisk / 100
		paf := float64(1 - user.UAuthSucTimes/user.UAuthTimes)
		pacf := float64(1 - user.AccessSucTimes/user.AccessTimes)
		psac := float64(user.AccessTimes-user.LegalAccTimes) / float64(parseTimeToUnix(getTime())-parseTimeToUnix(user.AccessTS))
		pbf := 0.2 * (paf + pacf + psac + frl)
		user.UserRisk = pbf * pff / px
		//计算用户行为分数
		user.UserBHScore = user.UserReputation - user.UserRisk

	} else {
		uLevelHist := user.UserLevel
		pf := (user.UserReputation - user.UserRisk) / user.UserReputation
		pas := (gateway.UAuthSucTimes / gateway.GwAuthTimes) * (user.UAuthSucTimes / user.AccessSucTimes)
		pacs := (gateway.UserAccessSucTimes / gateway.UserAccessTimes) * (user.AccessSucTimes / user.AccessTimes)
		plaf := user.LegalAccTimes / user.AccessTimes
		var frl float64
		if queryResource > 30 || queryResource < 0 {
			return shim.Error("No resources")
		} else if queryResource > (user.UserPrivilege + user.UserLevel) {
			frl = 1
		} else {
			frl = math.Floor(float64(1 - ((queryResource - user.UserPrivilege + user.UserLevel) / queryResource)))
		}
		pb := math.Pow(float64(pas), 2) * math.Pow(float64(pacs), 3) * math.Pow(float64(plaf), 2) * math.Pow(frl, 3)
		px := float64(gateway.UAuthSucTimes/gateway.GwAuthTimes) * float64(gateway.UserAccessSucTimes/gateway.UserAccessTimes) * ((float64(gateway.AccessUserNumber-1)*gateway.FL + frl) / float64(gateway.AccessUserNumber))
		user.UserReputation = pb * pf / px
		//计算用户风险值
		pff := user.UserRisk / 100
		paf := float64(1 - user.UAuthSucTimes/user.UAuthTimes)
		pacf := float64(1 - user.AccessSucTimes/user.AccessTimes)
		psac := float64(user.AccessTimes-user.LegalAccTimes) / float64(parseTimeToUnix(getTime())-parseTimeToUnix(user.AccessTS))
		pbf := 0.2 * (paf + pacf + psac + frl)
		user.UserRisk = pbf * pff / px
		user.UserBHScore = user.UserReputation - user.UserRisk

		//调整用户等级
		if user.UserBHScore < 60 {
			return shim.Error("User bh score is less than 60")
		} else if math.Abs(user.UserBHScore-float64(uLevelHist)) > 1 {
			user.UserLevel = math.Min(user.UserPrivilege+10, math.Max(user.UserPrivilege, uLevelHist+0.5*(user.UserBHScore-uLevelHist)))
		}
	}

}

// 计算信誉值
func (t *SimpleChaincode) calculateReputation(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	user := User{
		ASF:  0.8,
		AC:   1.0,
		ACC:  1.0,
		ACSF: 0.5,
		LAC:  0.2,
		SACF: 0.1,
		ACF:  0.9,
		MTP:  0.05,
		CARL: 2.0,
		CAPL: 1.5,
		HBHS: 0,
	}

	gateway := Gateway{
		GASF:  0.8,
		GAC:   1.0,
		GACSF: 0.6,
		GACC:  1.1,
		GRV:   0.9,
	}

	// delta值
	delta := map[string]float64{
		"P_AS":  0.2,
		"P_ACS": 0.3,
		"P_LAF": 0.1,
		"f_RL1": 0.4,
	}
	// 计算各概率，确保除法结果是浮动数
	var P_AS, P_ACS, P_LAF, f_RL float64

	if user.AC >= 0 && gateway.GAC >= 0 {
		P_AS = (user.ASF / user.AC) * (gateway.GASF / gateway.GAC)
	} else {
		return errors.New("Invalid values for AC or GAC")
	}

	if user.ACC >= 0 && gateway.GACC >= 0 {
		P_ACS = (user.ACSF / user.ACC) * (gateway.GACSF / gateway.GACC)
		P_LAF = user.LAC / user.ACC
	} else {
		return errors.New("Invalid values for ACC or GACC")
	}

	// 判断 CARL 和 CAPL
	if user.CARL <= user.CAPL {
		f_RL = 1
	} else if user.CAPL > 0 {
		f_RL = math.Max(user.CAPL/(user.CARL-user.CAPL), 2)
	} else {
		f_RL = 1
	}

	// 判断 ACC - ACSF 是否超过阈值 n，调整信誉值
	reputationPenalty := 1
	if (user.ACC-user.ACSF) > 1 || (user.SACF/user.ACF) > 0.05 || user.MTP > 0.1 {
		reputationPenalty = 3
	}

	// 联合概率
	P_X_given_theta_plus := (P_AS * delta["P_AS"]) + (P_ACS * delta["P_ACS"]) + (P_LAF * delta["P_LAF"]) + (f_RL * delta["f_RL1"])

	// 先验概率
	P_X := (gateway.GASF / gateway.GAC) * (gateway.GACSF / gateway.GACC) * f_RL
	P_theta_plus := gateway.GRV
	if user.HBHS != 0 {
		P_theta_plus = user.HBHS
	}

	// 信誉值计算
	R_U_plus := (P_X_given_theta_plus * P_theta_plus) / (P_X * float64(reputationPenalty))
	R_U_plus = 1 / (1 + math.Exp(-R_U_plus))

	return R_U_plus
}

// 计算风险值
func (t *SimpleChaincode) calculateRisk(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	user := User{
		ASF:  0.8,
		AC:   1.0,
		ACC:  1.0,
		ACSF: 0.5,
		LAC:  0.2,
		SACF: 0.1,
		ACF:  0.9,
		MTP:  0.05,
		CARL: 2.0,
		CAPL: 1.5,
		HBHR: 0,
	}

	gateway := Gateway{
		GASF:  0.8,
		GAC:   1.0,
		GACSF: 0.6,
		GACC:  1.1,
		GRR:   0.9,
	}

	// sigma值
	sigma := map[string]float64{
		"P_AF":      0.2,
		"P_ACF":     0.3,
		"f_RL2":     0.4,
		"P_SAC":     0.1,
		"MTP_index": 0.5,
	}
	// 计算各概率，确保除法结果是浮动数
	var P_AF, P_ACF, f_RL, P_SAC float64

	if user.AC > 0 {
		P_AF = 1 - (user.ASF / user.AC)
	} else {
		P_AF = 0
	}

	if user.ACC > 0 {
		P_ACF = 1 - (user.ACSF / user.ACC)
	} else {
		P_ACF = 0
	}

	// 判断 CARL 和 CAPL
	if user.CARL <= user.CAPL {
		f_RL = 1
	} else if user.CAPL > 0 {
		f_RL = math.Max(user.CAPL/(user.CARL-user.CAPL), 2)
	} else {
		f_RL = 1
	}

	if user.ACF > 0 {
		P_SAC = user.SACF / user.ACF
	} else {
		P_SAC = 0
	}

	// 判断 ASF-ACSF 和 ACC-ACSF 是否超过阈值 n，调整风险值
	riskBoost := 1.0
	if (user.ACC-user.ACSF) > 1 || P_SAC > 0.05 || user.MTP > 0.1 {
		riskBoost = 0.5
	}

	// 联合概率
	P_X_given_theta_minus := (sigma["P_AF"] * P_AF) + (sigma["P_ACF"] * P_ACF) + (sigma["f_RL2"] * f_RL) + (sigma["P_SAC"] * P_SAC) + (sigma["MTP_index"] * user.MTP)

	// 先验概率
	P_X := (gateway.GASF / gateway.GAC) * (gateway.GACSF / gateway.GACC) * f_RL
	P_theta_minus := gateway.GRR
	if user.HBHR != 0 {
		P_theta_minus = user.HBHR
	}

	// 风险值计算
	R_U_minus := (P_X_given_theta_minus * P_theta_minus) / (P_X * riskBoost)
	R_U_minus = 1 / (1 + math.Exp(-R_U_minus))

	return R_U_minus
}

// 计算行为分数
func (t *SimpleChaincode) calculateBehaviorScores(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	scores := (alpha*reputations - beta*risks) * 10
	scores = math.Max(0.0, math.Min(scores, 1.0))
	smoothedBehaviorScore := 0.8*user.behaviorScore + 0.2*scores
	return smoothedBehaviorScore
}

// 计算网关值
func (t *SimpleChaincode) calculateGatewayValues(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	reputation := (user.ACF*user.HBHS + gateway.UserNum*gateway.GRV) / (user.ACF + gateway.UserNum)
	reputation = 1 / (1 + math.Exp(-reputation))

	risk := (user.ACF*user.HBHR + gateway.UserNum*gateway.GRR) / (user.ACF + gateway.UserNum)
	risk = 0.5 / (1 + math.Exp(-risk))

	return shim.Success(reputation, risk)
}

// 更新用户状态
func (t *SimpleChaincode) updateUserStats(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// 示例：初始化用户和网关数据
	user := User{
		ACF:           0.6,
		HBHS:          0.8,
		HBHR:          0.3,
		behaviorScore: 0.7,
		CAPL:          15,
		CARL:          20,
		SACF:          0.5,
		MTP:           0.2,
	}

	gateway := Gateway{
		GACC:    10,
		UserNum: 1000,
		GRV:     0.7,
		GRR:     0.4,
	}

	delta := map[string]float64{"P_AS": 0.3, "P_ACS": 0.2, "P_LAF": 0.1, "f_RL1": 0.4}
	sigma := map[string]float64{"P_AF": 0.3, "P_ACF": 0.2, "f_RL2": 0.4, "P_SAC": 0.1, "MTP_index": 0.5}

	// 计算信誉值、风险值
	user.HBHS = calculateReputation(user, gateway, delta)
	user.HBHR = calculateRisk(user, gateway, sigma)

	// 计算行为分数
	behaviorScoreNew := calculateBehaviorScores(user, user.HBHS, user.HBHR, 0.5, 0.5)
	user.behaviorScore = behaviorScoreNew

	// 更新网关值
	gateway.GACC += 1
	gateway.GRV, gateway.GRR = calculateGatewayValues(user, gateway)

	return shim.Success(user, gateway)
}

// 更新用户访问等级
func (t *SimpleChaincode) updateCapl(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// 示例：初始化用户和网关数据
	user := User{
		ACF:           0.6,
		HBHS:          0.8,
		HBHR:          0.3,
		behaviorScore: 0.7,
		CAPL:          15,
		CARL:          20,
		SACF:          0.5,
		MTP:           0.2,
	}

	// 确定当前 CAPL 的范围区间
	caplRanges := [][2]int{{0, 9}, {10, 19}, {20, 29}}
	var caplNew float64
	for _, r := range caplRanges {
		if float64(r[0]) <= user.CAPL && user.CAPL <= float64(r[1]) {
			caplNew = user.CAPL
			break
		}
	}

	// 计算评分变化
	behaviorScoreChange := user.behaviorScore - behaviorScoreOld

	// 根据评分变化调整权限
	if math.Abs(behaviorScoreChange) >= 0.05 {
		if behaviorScoreChange > 0 {
			caplNew = user.CAPL + 1
		} else {
			caplNew = user.CAPL - 1
		}
	} else if math.Floor(user.CARL/10) > math.Floor(user.CAPL/10) {
		caplNew = user.CAPL - 10
	} else {
		caplNew = user.CAPL
	}

	// 检查其他调整条件
	if user.MTP > 0.1 {
		caplNew -= 1
	}
	if user.SACF/user.ACF > 0.05 && user.SACF != 1 {
		caplNew -= 1
	}

	// 限制权限级别在当前区间范围内
	for _, r := range caplRanges {
		caplNew = math.Max(float64(r[0]), math.Min(caplNew, float64(r[1])))
	}

	return caplNew
}

func main() {
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		fmt.Printf("\n--------------------------------Error starting Simple chaincode: %s--------------------------------\n", err)
	}
}
