package main

import (
	"encoding/json"
	"fmt"
)
import "time"
import "github.com/hyperledger/fabric/core/chaincode/shim"
import pb "github.com/hyperledger/fabric/protos/peer"

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
	GwState    string
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
	fmt.Println("3.update_gid_reg_state[gid, gw_verify_result]")
	fmt.Println("4.query_bc_pk[gid]")
	fmt.Println("5.query_gw_pk[gid]")
	fmt.Println("6.query_gw_hash_info[gid]")
	fmt.Println("7.update_gid_auth_state[gid, gid_auth_verify_result]")
	fmt.Println("8.query_uid_state[uid]")
	fmt.Println("9.register_uid[uid, user_hash_info, gateway_pk, gateway_sig_pk, user_pk, user_sig_pk]")
	fmt.Println("10.update_uid_reg_state[uid, user_reg_verify_result]")
	fmt.Println("11.query_user_hash_info[uid]")
	fmt.Println("12.update_uid_auth_state[uid, auth_result]")
	fmt.Println("13.query_gateway_pk[uid]")
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
	case "update_gid_reg_state":
		return t.update_gid_reg_state(stub, args)
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
	case "update_uid_reg_state":
		return t.update_uid_reg_state(stub, args)
	case "query_user_hash_info":
		return t.query_user_hash_info(stub, args)
	case "update_uid_auth_state":
		return t.update_uid_auth_state(stub, args)
	case "query_gateway_pk":
		return t.query_gateway_pk(stub, args)
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
	state, err := stub.GetState(GID + ".State")
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get register state for GID %s: %s", GID, err.Error()))
	}
	if state == nil || len(state) == 0 {
		return shim.Success([]byte("00"))
	}
	return shim.Success(state)
}

//2.上传网关注册信息
func (t *SimpleChaincode) register_gid(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var blockchain BCInfo
	var gateway GWInfo
	var err error

	txid := stub.GetTxID()
	if len(args) != 6 {
		return shim.Error("Incorrect number of arguments. Expecting 6")
	}

	bytes, err := stub.GetState(args[0])
	if err != nil {
		fmt.Printf("get state failed. Error: %s", err)
		return shim.Error("Failed to get state")
	}
	if bytes != nil {
		fmt.Printf("Register error. User '%s' already existed\n", args[0])
		return shim.Success([]byte("Register error. User " + args[0] + " already registered!+++" + txid))
	}
	// 参数解析
	gateway.GID = args[0]
	blockchain.BcPk = args[1]
	blockchain.BcSigPk = args[2]
	gateway.GwPk = args[3]
	gateway.GwSigPk = args[4]
	gateway.GwHashInfo = args[5]

	bytes, err = json.Marshal(gateway)
	if err != nil {
		fmt.Println("Error marshalling gateway")
		return shim.Error("Error marshalling gateway")
	}
	err = stub.PutState(gateway.GID, bytes)
	if err != nil {
		fmt.Println("PutState error.")
		return shim.Error("PutState error.")
	}

	bytes2, err = json.Marshal(blockchain)
	if err != nil {
		fmt.Println("Marshal error.")
		return shim.Error("Marshal error.")
	}
	err = stub.PutState("BCInfo_"+gateway.GID, bytes2)
	if err != nil {
		fmt.Println("PutState error.")
		return shim.Error("PutState error.")
	}
	return shim.Success([]byte("true"))
}

//3.更新注册状态
func (t *SimpleChaincode) update_gid_reg_state(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var gateway GWInfo
	var err error
	if len(args) != 2 {
		fmt.Println("Incorrect number of arguments. Expecting 2")
		return shim.Error("Incorrect number of arguments. Expecting 2")
	}
	gateway.GID = args[0]
	if args[1] == "True" {
		gateway.GwState = "10"
	} else {
		gateway.GwState = "00"
	}
	bytes
}

//4.查询区块链公钥
func (t *SimpleChaincode) query_bc_pk(stub shim.ChaincodeStubInterface, args []string) pb.Response {

}

//5.查询网关公钥
func (t *SimpleChaincode) query_gw_pk(stub shim.ChaincodeStubInterface, args []string) pb.Response {

}

//6.查询网关身份信息
func (t *SimpleChaincode) query_gw_hash_info(stub shim.ChaincodeStubInterface, args []string) pb.Response {
}

//7.更新网关注册状态
func (t *SimpleChaincode) update_gid_auth_state(stub shim.ChaincodeStubInterface, args []string) pb.Response {
}

//8.查询uid状态
func (t *SimpleChaincode) query_uid_state(stub shim.ChaincodeStubInterface, args []string) pb.Response {
}

//9.uid注册
func (t *SimpleChaincode) register_uid(stub shim.ChaincodeStubInterface, args []string) pb.Response {
}

//10.更新注册状态
func (t *SimpleChaincode) update_uid_reg_state(stub shim.ChaincodeStubInterface, args []string) pb.Response {
}

//11.查询用户身份信息
func (t *SimpleChaincode) query_user_hash_info(stub shim.ChaincodeStubInterface, args []string) pb.Response {
}

//12.更新uid认证状态
func (t *SimpleChaincode) update_uid_auth_state(stub shim.ChaincodeStubInterface, args []string) pb.Response {
}

//13.查询网关公钥
func (t *SimpleChaincode) query_gateway_pk(stub shim.ChaincodeStubInterface, args []string) pb.Response {
}

// 链码主入口
func main() {
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		fmt.Printf("\n-----------------Error starting Simple chaincode: %s--------------------\n", err)
	}
}
