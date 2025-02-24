package main

import (
	"encoding/json"
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

func main() {
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		fmt.Printf("\n--------------------------------Error starting Simple chaincode: %s--------------------------------\n", err)
	}
}
