package main

import (

	// "encoding/json"

	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
)

// SimpleChaincode example simple Chaincode implementation
type SimpleChaincode struct {
}

type BehaviorInfo struct {
	UID                  string
	Authen_success_times int64
	Authen_fail_times    int64
	ABAC_success_times   int64
	ABAC_fail_times      int64
	LISP_success_times   int64
	LISP_fail_times      int64
	Credit_score         []float64
	Authen_record        []string
	ABAC_record          []string
	LISP_record          []string
	Credit_record        []string
}

type UserInfo struct {
	SUPI          string
	Sqn           string
	K             string
	Role          string
	Cluster       string
	Priviledge    string
	K_SEAF        string
	Is_register   string
	Register_time string
	Is_authen     string
	Authen_time   string
}

type SEAFInfo struct {
	SNID       string
	PublicKey  string
	PrivateKey string
}

func get_time() string {
	time_stamp := time.Now().Unix()
	time_stamp += 8 * 60 * 60
	time_unix := time.Unix(time_stamp, 0)
	time_string := time_unix.Format("2006/01/02 15:04:05")
	return time_string
}

func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	fmt.Printf("----------------------------------Authen Chaincode Init Begins at %s----------------------------------\n", get_time())
	fmt.Println("Here you can invoke belowing functions:")
	fmt.Println("query_all")
	fmt.Println("get_K_SEAF : [SUPI]")
	fmt.Println("query_SUPI : [SUPI]")
	fmt.Println("renew_SUPI : [SUPI]")
	fmt.Println("check_SNID : [SNID]")
	fmt.Println("check_SUPI : [SUPI]")
	fmt.Println("delete_SNID : [SNID]")
	fmt.Println("delete_SUPI : [SUPI]")
	fmt.Println("get_AUSF_PublicKey : [SNID]")
	fmt.Println("get_AUSF_PrivateKey : [SNID]")
	fmt.Println("get_sqn_and_sharedKey : [SUPI]")
	fmt.Println("update_authen_result : [SUPI,authen_result]")
	fmt.Println("register_SNID : [SNID,PrivateKey,PublicKey]")
	fmt.Println("register_user : [SUPI,sqn,K,role,cluster,Priviledge]")
	fmt.Printf("----------------------------------Authen Chaincode Init  Ends  at %s----------------------------------\n", get_time())
	var gateway_1 SEAFInfo
	gateway_1.SNID = "Gateway.51.1.1.1"
	gateway_1.PrivateKey = "-----BEGIN RSA PRIVATE KEY-----\nMIICYAIBAAKBgQCJQyt3/W1f6FfG8l8xm7aoK2Qq1kzQAnHubj7jGkKkIu+iZ87+\nB8HSMGml/vVtKxWlKKry9tQclcjNO+MB7K/t6W0ZEbNJA31tKfXoyL86B0gw0gTK\nTIKF7m8A/8QjX/bGRHXu46dGVuEgq8OXutojNAxDkSTzXPcCXoonWJVNTwIDAQAB\nAoGAZGpHOpijky4eSOS2z0vi7FQSC2SK/QFM5+ivCOUFK56DQIRA4YY7PNE9+Ln0\nQdDrHNALf4Mi2WaaZ8oPVokwjl/oWcPOkE2Ue0WB/Nl0P5c/ag3dyoPM88VFeB+N\nEI/v+8T71c+9RefofnXgUOq/OpqVGVcdjF7InTDO9np5BkECRQC8Kmrb7Pp7CSbo\nUaqFiugKpWQNuDXKqqIAq7GF1tgNldquRaLxyTQI6U7Nl/0jdhi64UyZXZ1+4Saj\ngxCrhkE1vNoSxQI9ALq+8qRW2C5G5z+HqSqR0xtoAzIDBxguonvNtn7/IPTzdQ26\n+Kbe2M7r/3EPh9X+Py9f47Kse93xWCgRAwJEOVhgCrh1Oev3HJRO+LX1s9Dl5jx+\nwE4yYyvwRU7Nt441ACme2DsujYy1BHlOn3ENZl7lXlQmfJWXlfuKqAuZcgwlFdUC\nPBHSzbfPrhxkmgefPA8bEeoIuF1amp+9O7bTQHrIgO3AGsjvsnHCzTCap6uzzsQm\n2wL7hPD1s3DQaxiP3wJFAIlsiNtoC9v5wyyobO5n/UT+IBzNr+E2f3kbTipR1qhW\nyACRBngcCGbmahEuC8qFyVwdxToH70v4LWht+b5Y5OtXT96g\n-----END RSA PRIVATE KEY-----\n"
	gateway_1.PublicKey = "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAIlDK3f9bV/oV8byXzGbtqgrZCrWTNACce5uPuMaQqQi76Jnzv4HwdIw\naaX+9W0rFaUoqvL21ByVyM074wHsr+3pbRkRs0kDfW0p9ejIvzoHSDDSBMpMgoXu\nbwD/xCNf9sZEde7jp0ZW4SCrw5e62iM0DEORJPNc9wJeiidYlU1PAgMBAAE=\n-----END RSA PUBLIC KEY-----\n"
	err := stub.PutState(gateway_1.SNID+".private", []byte(gateway_1.PrivateKey))
	if err != nil {
		fmt.Println("Putstate error.")
		return shim.Error("Putstate error.")
	}
	err = stub.PutState(gateway_1.SNID+".public", []byte(gateway_1.PublicKey))
	if err != nil {
		fmt.Println("Putstate error.")
		return shim.Error("Putstate error.")
	}
	err = stub.PutState(gateway_1.SNID, []byte("authority"))
	if err != nil {
		fmt.Println("Putstate error.")
		return shim.Error("Putstate error.")
	}
	var gateway_2 SEAFInfo
	gateway_2.SNID = "Gateway.51.1.2.1"
	gateway_2.PrivateKey = "-----BEGIN RSA PRIVATE KEY-----\nMIICYQIBAAKBgQDmy6wI7kNnlpVZyEq+R7xXbTjCi+ZP9AwZez3602MKJ/zuR/O8\nXZFUyC9OZIiYrnPAxD6A0lRKGuhCK4fGSteMww326d879NIMx3E8xc6Z9217Bib9\nA68JCkyJfqX5rj/wDd7Ofn0abejzLVdhmzi2milpnAN3sVmNj8ot9Xo8FQIDAQAB\nAoGACt/t6z3Oz0K5JtHZM74NkdEDq6cL4xiMuWalNPxg3kmkEVYyld2Sy3vjPr5d\n8VPHAH4+s7M1ZYh/CR8j6tlECO89Vc4x3pMh7qCaS4dBYNbwle4xqR22KUKaB+4L\nPkfNUXVhe5HQbX9lnPD+s0/25LgWadAMNoqeXEEnnWVXaAECRQD6QaZKK1KFNT8E\nBlnUIRNv4nmj/GZT38WiFGO2dHk9ZqudD2iu5MZzLlEIWtdvUP9c7fyUW6sZOYbh\n42UGAeYLNeiGIQI9AOwXrsJa7UDwkq0pBYVsOaW5KbeC77/arZnWZitgxV6UE30K\nIWa1t5CyjI373L3TKkb7X3SfeFj7NTkPdQJFAKMId9Pj60uax6XQmV7H+YivSz2Y\n5fUIWBFiJR+tO3rT00Nr0W/23I4XA3Vk8Oq1ItegtybTnWC+iG/Km3rRa9Or2ALh\nAj0AsoWl6+j9hiFjh/SA7EbNwHanCNDFoXkl1DG+yAZAuCeYJPDIGPZHe+7HQYW1\ngQRv74ScxX7gbchmkmMRAkQpBTTH0oer7pgLyRn/en+CgDflYn7mIFb7d4Bz+gX4\n0Sj4+bd8eXTdVT9vxX7N/y7GGiH0cyQce3icpI4OMobkfK6hLQ==\n-----END RSA PRIVATE KEY-----\n"
	gateway_2.PublicKey = "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAObLrAjuQ2eWlVnISr5HvFdtOMKL5k/0DBl7PfrTYwon/O5H87xdkVTI\nL05kiJiuc8DEPoDSVEoa6EIrh8ZK14zDDfbp3zv00gzHcTzFzpn3bXsGJv0DrwkK\nTIl+pfmuP/AN3s5+fRpt6PMtV2GbOLaaKWmcA3exWY2Pyi31ejwVAgMBAAE=\n-----END RSA PUBLIC KEY-----\n"
	err = stub.PutState(gateway_2.SNID+".private", []byte(gateway_2.PrivateKey))
	if err != nil {
		fmt.Println("Putstate error.")
		return shim.Error("Putstate error.")
	}
	err = stub.PutState(gateway_2.SNID+".public", []byte(gateway_2.PublicKey))
	if err != nil {
		fmt.Println("Putstate error.")
		return shim.Error("Putstate error.")
	}
	err = stub.PutState(gateway_2.SNID, []byte("authority"))
	if err != nil {
		fmt.Println("Putstate error.")
		return shim.Error("Putstate error.")
	}
	var gateway_3 SEAFInfo
	gateway_3.SNID = "Gateway.51.1.3.1"
	gateway_3.PrivateKey = "-----BEGIN RSA PRIVATE KEY-----\nMIICXwIBAAKBgQCMjZXYOOXYBM43u6TSDUzeEK0oYm0FrjdBf6mIkqh6X8eFLUTT\nms8XhLAFsuFpDnMkmnXC8VptPXoTPmnGkRr/2i7ig+NxclC/qXJqmgoL5tWNIHnI\nmCsE3qNg1UMgSPMZHYVlIuN1P9juUPFimC9CM7U9jv5yF0txZVtd4IyE/wIDAQAB\nAoGAI9xH/AfgVLI9LykYD2PHVe0pUOFz8XwWqwZ4adkJVVe0nz0Cj36zEcwP4RRX\nwKcoJ5GlNBzCNpb1240T3Wead/qISdShJ5NBX//NWo9iE4vq46OaXkMF8Fu01PYo\n96aLOlf8m/HaElnvsDNwZUk4CeURfs99Ppb5ve8Kq16kKdECRQC9td3vEokWF964\nVYGnR6BB1DyFUSqgAjMJHsdXfUjiG/H75wAB4/6hNblOvLdnlZQVjXIaeO3Qkn3A\nQr0itWNvOusSuQI9AL2qdFpSQGTDXNepfeJqswtct9YNmCU4kryTbyYTNc6KQvZO\nr49rhh9Ex8hr8yElC2Ieg2Rb7xUu+ajZdwJELwKSLFv7fG4N0r/dkQY+wBFHrgGe\n/meNHgVygEubc+xY2oMzjURiJLCbatd420JFn9GdJNIynCyw3KOtGpy4NyfyeIEC\nPDaSmiH28rJLiCZBjYgdXWESj47WoIVtLsN1xJB3DI9eNwA6CcfBj3jlyHpBnVZX\nG1xjHTk+Pp+gwZM05wJES7tPafxb4PViH4s6neyl41qrdz18kdhPgDVcI8fKbBmS\nGSXwyn6erI/cLczZmCBs9PejWytLgXLj6NSJ6MxgsYx3fSE=\n-----END RSA PRIVATE KEY-----\n"
	gateway_3.PublicKey = "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAIyNldg45dgEzje7pNINTN4QrShibQWuN0F/qYiSqHpfx4UtRNOazxeE\nsAWy4WkOcySadcLxWm09ehM+acaRGv/aLuKD43FyUL+pcmqaCgvm1Y0geciYKwTe\no2DVQyBI8xkdhWUi43U/2O5Q8WKYL0IztT2O/nIXS3FlW13gjIT/AgMBAAE=\n-----END RSA PUBLIC KEY-----\n"
	err = stub.PutState(gateway_3.SNID+".private", []byte(gateway_3.PrivateKey))
	if err != nil {
		fmt.Println("Putstate error.")
		return shim.Error("Putstate error.")
	}
	err = stub.PutState(gateway_3.SNID+".public", []byte(gateway_3.PublicKey))
	if err != nil {
		fmt.Println("Putstate error.")
		return shim.Error("Putstate error.")
	}
	err = stub.PutState(gateway_3.SNID, []byte("authority"))
	if err != nil {
		fmt.Println("Putstate error.")
		return shim.Error("Putstate error.")
	}
	return shim.Success([]byte("\nAKA-Authen Chaincode Init at " + get_time()))
}

func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	function, args := stub.GetFunctionAndParameters()
	if function == "register_user" {
		return t.register_user(stub, args)
	} else if function == "register_SNID" {
		return t.register_SNID(stub, args)
	} else if function == "Get_AUSF_PrivateKey" {
		return t.Get_AUSF_PrivateKey(stub, args)
	} else if function == "Get_AUSF_PublicKey" {
		return t.Get_AUSF_PublicKey(stub, args)
	} else if function == "query_all" {
		return t.query_all(stub, args)
	} else if function == "check_SNID" {
		return t.check_SNID(stub, args)
	} else if function == "check_SUPI" {
		return t.check_SUPI(stub, args)
	} else if function == "get_sqn_and_sharedKey" {
		return t.get_sqn_and_sharedKey(stub, args)
	} else if function == "update_authen_result" {
		return t.update_authen_result(stub, args)
	} else if function == "query_SUPI" {
		return t.query_SUPI(stub, args)
	} else if function == "delete_SNID" {
		return t.delete_SNID(stub, args)
	} else if function == "delete_SUPI" {
		return t.delete_SUPI(stub, args)
	} else if function == "renew_SUPI" {
		return t.renew_SUPI(stub, args)
	} else if function == "get_K_SEAF" {
		return t.get_K_SEAF(stub, args)
	} else if function == "renew_BI" {
		return t.renew_BI(stub, args)
	} else if function == "query_BI" {
		return t.query_BI(stub, args)
	} else if function == "BehaviorInfo2CSV" {
		return t.BehaviorInfo2CSV(stub, args)
	}
	fmt.Println("Invalid arguments:", function, args)
	return shim.Error("Invalid invoke function name. Expecting \"query_all\" \"register\" \"delete\" \"query\" \"authen\"")
}

//输入的参数args是uuid、密码、时间
func (t *SimpleChaincode) register_user(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	fmt.Printf("\n----------------------------------Authen Chaincode Register_user at %s----------------------------------\n", get_time())
	fmt.Printf("SUPI:%s\n", args[0])
	var userInfo UserInfo
	var bi BehaviorInfo
	var err error
	txid := stub.GetTxID()
	if len(args) != 6 {
		fmt.Println("Incorrect number of arguments.")
		return shim.Error("Incorrect number of arguments. Expecting SUPI,sqn,K,role,cluster and Priviledge!")
	}

	bytes, err := stub.GetState(args[0])
	if err != nil {
		fmt.Println("Getstate error.")
		return shim.Error("Getstate error.")
	}
	if bytes != nil {
		fmt.Printf("Register error. User '%s' already existed\n", args[0])
		return shim.Success([]byte("Register error. User " + args[0] + " already registered!+++" + txid))
	}
	userInfo.SUPI = args[0]
	userInfo.Sqn = args[1]
	userInfo.K = args[2]
	userInfo.Role = args[3]
	userInfo.Cluster = args[4]
	userInfo.Priviledge = args[5]
	userInfo.Is_register = "True"
	userInfo.Register_time = get_time()
	userInfo.Is_authen = "False"
	userInfo.Authen_time = "False"
	userInfo.K_SEAF = "False"

	bi.UID = args[0]
	bi.Authen_success_times = 0
	bi.Authen_fail_times = 0
	bi.ABAC_success_times = 0
	bi.ABAC_fail_times = 0
	bi.LISP_success_times = 0
	bi.LISP_fail_times = 0
	bi.Credit_score = []float64{100}

	bytes, err = json.Marshal(userInfo)
	if err != nil {
		fmt.Println("Marshal error.")
		return shim.Error("Marshal error.")
	}
	err = stub.PutState(userInfo.SUPI, bytes)
	if err != nil {
		fmt.Println("PutState error.")
		return shim.Error("PutState error.")
	}

	bytes2, err := json.Marshal(bi)
	if err != nil {
		fmt.Println("Marshal error.")
		return shim.Error("Marshal error.")
	}
	err = stub.PutState("BehaviorInfo_"+userInfo.SUPI, bytes2)
	if err != nil {
		fmt.Println("PutState error.")
		return shim.Error("PutState error.")
	}

	ret := string(bytes) + "+++" + txid

	fmt.Println("Register success, put state: ", userInfo, bi)
	return shim.Success([]byte(ret))
}

func (t *SimpleChaincode) register_SNID(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	fmt.Printf("\n----------------------------------Authen Chaincode Register_SNID at %s----------------------------------\n", get_time())
	fmt.Printf("SUPI:%s\n", args[0])
	var gateway SEAFInfo
	var err error
	gateway.SNID = args[0]
	gateway.PrivateKey = args[1]
	gateway.PublicKey = args[2]

	if len(args) != 3 {
		fmt.Println("Incorrect number of arguments.")
		return shim.Error("Incorrect number of arguments. Expecting SNID,privatekey and publickey!")
	}

	bytes, err := stub.GetState(args[0])
	if err != nil {
		fmt.Println("Getstate error.")
		return shim.Error("Getstate error.")
	}
	if bytes != nil {
		fmt.Printf("Register error. SNID '%s' already existed\n", args[0])
		return shim.Success([]byte("Register error. SNID " + args[0] + " already registered!"))
	}

	err = stub.PutState(gateway.SNID+".private", []byte(gateway.PrivateKey))
	if err != nil {
		fmt.Println("Putstate error.")
		return shim.Error("Putstate error.")
	}
	err = stub.PutState(gateway.SNID+".public", []byte(gateway.PublicKey))
	if err != nil {
		fmt.Println("Putstate error.")
		return shim.Error("Putstate error.")
	}
	err = stub.PutState(gateway.SNID, []byte("authority"))
	if err != nil {
		fmt.Println("Putstate error.")
		return shim.Error("Putstate error.")
	}

	txid := stub.GetTxID()
	ret := string(bytes)
	ret = ret + "+++" + txid
	return shim.Success([]byte(ret))
}

func (t *SimpleChaincode) Get_AUSF_PublicKey(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	fmt.Printf("\n----------------------------------Authen Chaincode Get_AUSF_PublicKey at %s----------------------------------\n", get_time())
	fmt.Printf("SNID:%s\n", args[0])
	var err error

	if len(args) != 1 {
		fmt.Println("Incorrect number of arguments.")
		return shim.Error("Incorrect number of arguments. Expecting SNID.")
	}

	SNID := args[0]

	// Get the state from the ledger
	bytes, err := stub.GetState(SNID + ".public")
	if err != nil {
		fmt.Println("Getstate error.")
		return shim.Error("Getstate error.")
	}

	if bytes == nil {
		fmt.Printf("Query error. %s doesn't register.\n", SNID)
		return shim.Error("Query error. Not register SNID:" + SNID)
	}

	fmt.Println("Successfully getstate:", string(bytes))

	return shim.Success(bytes)
}

func (t *SimpleChaincode) Get_AUSF_PrivateKey(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	fmt.Printf("\n----------------------------------Authen Chaincode Get_AUSF_PrivateKey at %s----------------------------------\n", get_time())
	fmt.Printf("SNID:%s\n", args[0])
	var err error

	if len(args) != 1 {
		fmt.Println("Incorrect number of arguments.")
		return shim.Error("Incorrect number of arguments. Expecting SNID.")
	}

	SNID := args[0]

	// Get the state from the ledger
	bytes, err := stub.GetState(SNID + ".private")
	if err != nil {
		fmt.Println("Getstate error.")
		return shim.Error("Getstate error.")
	}

	if bytes == nil {
		fmt.Printf("Query error. %s doesn't register.\n", SNID)
		return shim.Error("Query error. Not register SNID:" + SNID)
	}

	fmt.Println("Successfully getstate:", string(bytes))

	return shim.Success(bytes)
}

func (t *SimpleChaincode) check_SNID(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	fmt.Printf("\n----------------------------------Authen Chaincode check_SNID at %s----------------------------------\n", get_time())
	fmt.Printf("SNID:%s\n", args[0])
	var err error

	if len(args) != 1 {
		fmt.Println("Incorrect number of arguments.")
		return shim.Error("Incorrect number of arguments. Expecting SNID.")
	}

	SNID := args[0]

	// Get the state from the ledger
	bytes, err := stub.GetState(SNID)
	if err != nil {
		fmt.Println("Getstate error.")
		return shim.Error("Getstate error.")
	}

	if bytes == nil {
		fmt.Printf("Query error. %s doesn't register.\n", SNID)
		return shim.Success([]byte("False"))
	}

	fmt.Println("Successfully getstate:", string(bytes))

	return shim.Success(bytes)
}

func (t *SimpleChaincode) check_SUPI(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	fmt.Printf("\n----------------------------------Authen Chaincode check_SUPI at %s----------------------------------\n", get_time())
	fmt.Printf("SUPI:%s\n", args[0])
	var err error
	var userInfo UserInfo

	if len(args) != 1 {
		fmt.Println("Incorrect number of arguments.")
		return shim.Error("Incorrect number of arguments. Expecting SUPI.")
	}

	SUPI := args[0]

	// Get the state from the ledger
	bytes, err := stub.GetState(SUPI)
	if err != nil {
		fmt.Println("Getstate error.")
		return shim.Error("Getstate error.")
	}

	if bytes == nil {
		fmt.Printf("Query error. %s doesn't register.\n", SUPI)
		return shim.Success([]byte("False"))
	}

	err = json.Unmarshal(bytes, &userInfo)
	if userInfo.Is_register != "True" {
		fmt.Printf("Query error. %s doesn't register.\n", SUPI)
		return shim.Success([]byte("False"))
	}

	authen_time, _ := strconv.Atoi(userInfo.Authen_time)
	if int(time.Now().Unix()+8*60*60)-authen_time <= 3600 {
		if userInfo.Is_authen == "True" {
			fmt.Println("Successfully getstate:", string(bytes))
			return shim.Success([]byte(userInfo.K_SEAF))
		}
	}

	fmt.Println("Successfully getstate:", string(bytes))

	return shim.Success([]byte("True"))
}

func (t *SimpleChaincode) get_K_SEAF(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	fmt.Printf("\n----------------------------------Authen Chaincode get_K_SEAF at %s----------------------------------\n", get_time())
	fmt.Printf("SUPI:%s\n", args[0])
	var err error
	var userInfo UserInfo

	if len(args) != 1 {
		fmt.Println("Incorrect number of arguments.")
		return shim.Error("Incorrect number of arguments. Expecting SUPI.")
	}

	SUPI := args[0]

	// Get the state from the ledger
	bytes, err := stub.GetState(SUPI)
	if err != nil {
		fmt.Println("Getstate error.")
		return shim.Error("Getstate error.")
	}

	if bytes == nil {
		fmt.Printf("Query error. %s doesn't register.\n", SUPI)
		return shim.Success([]byte("False"))
	}

	err = json.Unmarshal(bytes, &userInfo)
	if userInfo.Is_register != "True" {
		fmt.Printf("Query error. %s doesn't register.\n", SUPI)
		return shim.Success([]byte("False"))
	}

	authen_time, _ := strconv.Atoi(userInfo.Authen_time)
	if int(time.Now().Unix()+8*60*60)-authen_time <= 3600 {
		fmt.Println("Successfully getstate:", string(bytes))
		return shim.Success([]byte(userInfo.K_SEAF))
	}

	fmt.Println("Successfully getstate:", string(bytes))

	return shim.Success([]byte("False"))
}

func (t *SimpleChaincode) get_sqn_and_sharedKey(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	fmt.Printf("\n----------------------------------Authen Chaincode get_sqn_and_sharedKey at %s----------------------------------\n", get_time())
	fmt.Printf("SUPI:%s\n", args[0])
	var userInfo UserInfo
	var err error

	if len(args) != 1 {
		fmt.Println("Incorrect number of arguments.")
		return shim.Error("Incorrect number of arguments. Expecting SUPI.")
	}

	SUPI := args[0]

	// Get the state from the ledger
	bytes, err := stub.GetState(SUPI)
	if err != nil {
		fmt.Println("Getstate error.")
		return shim.Error("Getstate error.")
	}

	if bytes == nil {
		fmt.Printf("Query error. %s doesn't register.\n", SUPI)
		return shim.Error("False")
	}

	err = json.Unmarshal(bytes, &userInfo)
	if err != nil {
		fmt.Println("Unmarshal error.")
		return shim.Error("Unmasharl error.")
	}
	if userInfo.Is_register != "True" {
		fmt.Printf("Query error. %s doesn't register.\n", SUPI)
		return shim.Error("False")
	}
	fmt.Println("Successfully getstate:", string(bytes))

	bytes = []byte(userInfo.Sqn + "++++++" + userInfo.K)

	return shim.Success(bytes)
}

func calculate_credit(IAS int64, IAF int64, ACS int64, ACF int64, SMS int64, SMF int64) float64 {
	w_ia, w_ac, w_sm := 0.4, 0.3, 0.3
	credit_ia := 100 * w_ia / (1 + math.Exp(0.1*float64(IAS-IAF)))
	credit_ac := 100 * w_ac / (1 + math.Exp(0.1*float64(ACS-ACF)))
	credit_sm := 100 * w_sm / (1 + math.Exp(0.1*float64(SMS-SMF)))
	return 100 - credit_ia - credit_ac - credit_sm
}

func (t *SimpleChaincode) update_authen_result(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	fmt.Printf("\n----------------------------------Authen Chaincode update_authen_result at %s----------------------------------\n", get_time())
	fmt.Printf("SUPI:%s\n", args[0])
	var err error
	var userInfo UserInfo
	var bi BehaviorInfo

	if len(args) != 5 {
		fmt.Println("Incorrect number of arguments.")
		return shim.Error("Incorrect number of arguments. Expecting SUPI and authen result.")
	}

	SUPI := args[0]
	result := args[1]
	K_SEAF := args[2]
	SNID := args[3]

	// Get the state from the ledger
	bytes, err := stub.GetState(SUPI)
	if err != nil {
		fmt.Println("Getstate error.")
		return shim.Error("Getstate error.")
	}

	if bytes == nil {
		fmt.Printf("Query error. %s doesn't register.\n", SUPI)
		return shim.Error("False")
	}

	err = json.Unmarshal(bytes, &userInfo)
	if err != nil {
		fmt.Println("Unmarshal error.")
		return shim.Error("Unmasharl error.")
	}

	bytes2, err := stub.GetState("BehaviorInfo_" + SUPI)
	if err != nil {
		fmt.Println("Getstate error.")
		return shim.Error("Getstate error.")
	}

	if bytes2 == nil {
		fmt.Printf("Query error. %s doesn't register.\n", SUPI)
		return shim.Error("False")
	}

	err = json.Unmarshal(bytes2, &bi)
	if err != nil {
		fmt.Println("Unmarshal error.")
		return shim.Error("Unmasharl error.")
	}

	if result == "Success" {
		bi.Authen_success_times++
		credit := calculate_credit(bi.Authen_success_times, bi.Authen_fail_times, bi.ABAC_success_times, bi.ABAC_fail_times, bi.LISP_success_times, bi.LISP_fail_times)
		var record = Record{"IA", SUPI, stub.GetTxID(), SNID, args[4], "Authentication Success", get_time(), bi.Authen_success_times, bi.Authen_fail_times, bi.ABAC_success_times, bi.ABAC_fail_times, bi.LISP_success_times, bi.LISP_fail_times, credit, []string{}}
		record_byte, _ := json.Marshal(record)
		bi.Authen_record = append(bi.Authen_record, string(record_byte))
		userInfo.Authen_time = strconv.Itoa(int(time.Now().Unix() + 8*60*60))
		userInfo.Is_authen = "True"
		userInfo.K_SEAF = K_SEAF
		fmt.Println("Successfully authen:", userInfo, bi.Authen_record[len(bi.Authen_record)-1])
	} else if result == "Fail" {
		bi.Authen_fail_times++
		credit := calculate_credit(bi.Authen_success_times, bi.Authen_fail_times, bi.ABAC_success_times, bi.ABAC_fail_times, bi.LISP_success_times, bi.LISP_fail_times)
		var record = Record{"IA", SUPI, stub.GetTxID(), SNID, args[4], "Authentication Fail", get_time(), bi.Authen_success_times, bi.Authen_fail_times, bi.ABAC_success_times, bi.ABAC_fail_times, bi.LISP_success_times, bi.LISP_fail_times, credit, []string{}}
		record_byte, _ := json.Marshal(record)
		bi.Authen_record = append(bi.Authen_record, string(record_byte))
		userInfo.Authen_time = "False"
		userInfo.Is_authen = "False"
		userInfo.K_SEAF = "False"
		fmt.Println("Authen failed:", userInfo, bi.Authen_record[len(bi.Authen_record)-1])
	} else {
		fmt.Println("Authen error.")
		return shim.Error("Authen error.")
	}

	bytes, err = json.Marshal(userInfo)
	if err != nil {
		fmt.Println("Marshal error.")
		return shim.Error("Marshal error.")
	}
	// Write the state to the ledger
	err = stub.PutState(userInfo.SUPI, bytes)
	if err != nil {
		fmt.Println("Putstate error.")
		return shim.Error("Putstate error.")
	}

	bytes2, err = json.Marshal(bi)
	if err != nil {
		fmt.Println("Marshal error.")
		return shim.Error("Marshal error.")
	}
	// Write the state to the ledger
	err = stub.PutState("BehaviorInfo_"+userInfo.SUPI, bytes2)
	if err != nil {
		fmt.Println("Putstate error.")
		return shim.Error("Putstate error.")
	}

	txid := stub.GetTxID()
	ret := string(bytes) + "+++" + txid
	return shim.Success([]byte(ret))
}

//查询所有uuid信息，无需参数
func (t *SimpleChaincode) query_all(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	fmt.Printf("\n----------------------------------Authen Chaincode Query_all at %s----------------------------------\n", get_time())

	keysIter, err := stub.GetStateByRange("", "")
	if err != nil {
		fmt.Println("Getstatebyrange error.")
		return shim.Error("Getstatebyrange error.")
	}

	rsp := make(map[string]string)

	for keysIter.HasNext() {
		response, interErr := keysIter.Next()
		if interErr != nil {
			return shim.Error(interErr.Error())
		}
		rsp[response.Key] = string(response.Value)
		fmt.Println(string(response.Value))
	}
	result := ""
	//将结果以字符串连接形式返回
	for _, value := range rsp {
		result = result + value + "~~~~~~"
	}
	result_bytes := []byte(result)
	result_bytes = result_bytes[:len(result_bytes)]
	return shim.Success(result_bytes)
}

// Deletes an entity from state
//参数args为用户的UUID
func (t *SimpleChaincode) delete_SUPI(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	fmt.Printf("\n----------------------------------Authen Chaincode Delete_SUPI at %s----------------------------------\n", get_time())
	fmt.Printf("SUPI:%s\n", args[0])
	if len(args) != 1 {
		fmt.Println("Incorrect number of arguments.")
		return shim.Error("Incorrect number of arguments. Expecting uuid.")
	}

	SUPI := args[0]
	bytes, err := stub.GetState(args[0])
	if err != nil {
		fmt.Println("Getstate error.")
		return shim.Error("Getstate error.")
	}
	if bytes == nil {
		fmt.Printf("Delete error. SUPI %s doesn't exist.\n", SUPI)
		return shim.Error("Delete error. SUPI " + SUPI + " doesn't exist.")
	}

	// Delete the key from the state in ledger
	err = stub.DelState(SUPI)
	if err != nil {
		fmt.Println("Delete error. Failed to delete " + SUPI)
		return shim.Error("Delete error. Failed to delete " + SUPI)
	}
	// err = stub.DelState("BehaviorInfo_" + SUPI)
	// if err != nil {
	// 	fmt.Println("Delete error. Failed to delete " + SUPI)
	// 	return shim.Error("Delete error. Failed to delete " + SUPI)
	// }
	fmt.Printf("Successfully delete %s\n", SUPI)
	return shim.Success([]byte("success"))
}

func (t *SimpleChaincode) delete_SNID(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	fmt.Printf("\n----------------------------------Authen Chaincode Delete_SNID at %s----------------------------------\n", get_time())
	fmt.Printf("SNID:%s\n", args[0])
	if len(args) != 1 {
		fmt.Println("Incorrect number of arguments.")
		return shim.Error("Incorrect number of arguments. Expecting uuid.")
	}

	SNID := args[0]
	bytes, err := stub.GetState(SNID)
	if err != nil {
		fmt.Println("Getstate error.")
		return shim.Error("Getstate error.")
	}
	if bytes == nil {
		fmt.Printf("Delete error. SNID %s doesn't exist.\n", SNID)
		return shim.Error("Delete error. SNID " + SNID + " doesn't exist.")
	}

	// Delete the key from the state in ledger
	err1 := stub.DelState(SNID)
	err2 := stub.DelState(SNID + ".private")
	err3 := stub.DelState(SNID + ".public")
	if err1 != nil || err2 != nil || err3 != nil {
		fmt.Println("Delete error. Failed to delete " + SNID)
		return shim.Error("Delete error. Failed to delete " + SNID)
	}
	fmt.Printf("Successfully delete %s\n", SNID)
	return shim.Success([]byte("successfully delete " + SNID))
}

// query callback representing the query of a chaincode
//需要参数args为UUID
func (t *SimpleChaincode) query_SUPI(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	fmt.Printf("\n----------------------------------Authen Chaincode Query at %s----------------------------------\n", get_time())
	fmt.Printf("SUPI:%s\n", args[0])
	var userInfo UserInfo
	var err error

	if len(args) != 1 {
		fmt.Println("Incorrect number of arguments.")
		return shim.Error("Incorrect number of arguments. Expecting uuid.")
	}

	SUPI := args[0]

	// Get the state from the ledger
	bytes, err := stub.GetState(SUPI)
	if err != nil {
		fmt.Println("Getstate error.")
		return shim.Error("Getstate error.")
	}

	if bytes == nil {
		fmt.Printf("Query error. %s doesn't register.\n", SUPI)
		return shim.Error("Query error. Not register uuid:" + SUPI)
	}

	err = json.Unmarshal(bytes, &userInfo)
	fmt.Println("Successfully getstate:", userInfo)

	return shim.Success(bytes)
}

func (t *SimpleChaincode) query_BI(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	fmt.Printf("\n----------------------------------Authen Chaincode Query_BI at %s----------------------------------\n", get_time())
	fmt.Printf("SUPI:%s\n", args[0])
	var bi BehaviorInfo
	var err error

	if len(args) != 1 {
		fmt.Println("Incorrect number of arguments.")
		return shim.Error("Incorrect number of arguments. Expecting uuid.")
	}

	SUPI := args[0]

	// Get the state from the ledger
	bytes, err := stub.GetState("BehaviorInfo_" + SUPI)
	if err != nil {
		fmt.Println("Getstate error.")
		return shim.Error("Getstate error.")
	}

	if bytes == nil {
		fmt.Printf("Query error. %s doesn't register.\n", SUPI)
		return shim.Error("Query error. Not register uuid:" + SUPI)
	}

	err = json.Unmarshal(bytes, &bi)
	fmt.Println("Successfully getstate:", bi)

	return shim.Success(bytes)
}

func (t *SimpleChaincode) renew_SUPI(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	fmt.Printf("\n----------------------------------Authen Chaincode renew_SUPI at %s----------------------------------\n", get_time())
	fmt.Printf("SUPI:%s\n", args[0])
	var err error
	var userInfo_old UserInfo
	var userInfo UserInfo

	if len(args) != 2 {
		fmt.Println("Incorrect number of arguments.")
		return shim.Error("Incorrect number of arguments. Expecting SUPI and SUPI's all info.")
	}

	SUPI := args[0]

	// Get the state from the ledger
	bytes, err := stub.GetState(SUPI)
	if err != nil {
		fmt.Println("Getstate error.")
		return shim.Error("Getstate error.")
	}

	if bytes == nil {
		fmt.Printf("Query error. %s doesn't register.\n", SUPI)
		return shim.Error("False")
	}

	err = json.Unmarshal(bytes, &userInfo_old)
	err = json.Unmarshal([]byte(args[1]), &userInfo)

	// Write the state to the ledger
	err = stub.PutState(SUPI, []byte(args[1]))
	if err != nil {
		fmt.Println("Putstate error.")
		return shim.Error("Putstate error.")
	}
	fmt.Println("userInfo_old:", userInfo_old)
	fmt.Println("userInfo_new:", userInfo)
	return shim.Success([]byte("successfully renew SUPI"))
}

type Record struct {
	Type      string
	UID       string
	Txid      string
	GID       string
	EID       string
	Result    string
	Time      string
	IAS       int64
	IAF       int64
	ACS       int64
	ACF       int64
	SMS       int64
	SMF       int64
	Credit    float64
	ExtraInfo []string
}

func (t *SimpleChaincode) renew_BI(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	fmt.Printf("\n----------------------------------Authen Chaincode renew_BI at %s----------------------------------\n", get_time())
	fmt.Printf("SUPI:%s\n", args[0])
	var err error
	var bi BehaviorInfo

	if len(args) != 4 {
		fmt.Println("Incorrect number of arguments.")
		return shim.Error("Incorrect number of arguments. Expecting SUPI and SUPI's all info.")
	}

	SUPI := args[0]

	// Get the state from the ledger
	bytes, err := stub.GetState("BehaviorInfo_" + SUPI)
	if err != nil {
		fmt.Println("Getstate error.")
		return shim.Error("Getstate error.")
	}

	if bytes == nil {
		fmt.Printf("Query error. %s doesn't register.\n", SUPI)
		return shim.Error("False")
	}

	err = json.Unmarshal(bytes, &bi)

	var record Record
	err = json.Unmarshal([]byte(args[3]), &record)

	if args[1] == "ac" {
		if args[2] == "True" {
			bi.ABAC_success_times++
		} else {
			bi.ABAC_fail_times++
		}
		record.IAS = bi.Authen_success_times
		record.IAF = bi.Authen_fail_times
		record.ACS = bi.ABAC_success_times
		record.ACF = bi.ABAC_fail_times
		record.SMS = bi.LISP_success_times
		record.SMF = bi.LISP_fail_times
		record.Credit = calculate_credit(bi.Authen_success_times, bi.Authen_fail_times, bi.ABAC_success_times, bi.ABAC_fail_times, bi.LISP_success_times, bi.LISP_fail_times)
		record_byte, _ := json.Marshal(record)
		bi.ABAC_record = append(bi.ABAC_record, string(record_byte))
		fmt.Println(bi.ABAC_record[len(bi.ABAC_record)-1])
	} else if args[1] == "sm" {
		if args[2] == "True" {
			bi.LISP_success_times++
		} else {
			bi.LISP_fail_times++
		}
		record.IAS = bi.Authen_success_times
		record.IAF = bi.Authen_fail_times
		record.ACS = bi.ABAC_success_times
		record.ACF = bi.ABAC_fail_times
		record.SMS = bi.LISP_success_times
		record.SMF = bi.LISP_fail_times
		record.Credit = calculate_credit(bi.Authen_success_times, bi.Authen_fail_times, bi.ABAC_success_times, bi.ABAC_fail_times, bi.LISP_success_times, bi.LISP_fail_times)
		record_byte, _ := json.Marshal(record)
		bi.LISP_record = append(bi.LISP_record, string(record_byte))
		fmt.Println(bi.LISP_record[len(bi.LISP_record)-1])
	} else {
		record.IAS = bi.Authen_success_times
		record.IAF = bi.Authen_fail_times
		record.ACS = bi.ABAC_success_times
		record.ACF = bi.ABAC_fail_times
		record.SMS = bi.LISP_success_times
		record.SMF = bi.LISP_fail_times
		credit, _ := strconv.ParseFloat(args[2], 64)
		bi.Credit_score = append(bi.Credit_score, credit)
		bi.Credit_record = append(bi.Credit_record, args[3])
		fmt.Println(bi.Credit_record[len(bi.Credit_record)-1])
	}

	bytes, err = json.Marshal(bi)

	// Write the state to the ledger
	err = stub.PutState("BehaviorInfo_"+SUPI, bytes)
	if err != nil {
		fmt.Println("Putstate error.")
		return shim.Error("Putstate error.")
	}
	// fmt.Println(bi)
	return shim.Success([]byte("successfully renew BI"))
}

func BytesPrefix(prefix []byte) []byte {
	var limit []byte
	for i := len(prefix) - 1; i >= 0; i-- {
		c := prefix[i]
		if c < 0xff {
			limit = make([]byte, i+1)
			copy(limit, prefix)
			limit[i] = c + 1
			break
		}
	}
	return limit
}

func (t *SimpleChaincode) BehaviorInfo2CSV(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	fmt.Printf("\n----------------------------------Authen Chaincode BehaviorInfo2CSV at %s----------------------------------\n", get_time())
	type ReuturnBI struct {
		BI    []BehaviorInfo
		Error string
	}
	var ret ReuturnBI
	startKey := args[0]
	endKey := string(BytesPrefix([]byte(startKey)))
	resultsIterator, err := stub.GetStateByRange(startKey, endKey)
	defer resultsIterator.Close()
	if err != nil {
		fmt.Println("GetStateByRange error.")
		ret.Error = "GetStateByRange error."
		bytes, _ := json.Marshal(ret)
		return shim.Success(bytes)
	}
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			fmt.Println("IteratorNext error.")
			ret.Error = "IteratorNext error."
			bytes, _ := json.Marshal(ret)
			return shim.Success(bytes)
		}
		var bi BehaviorInfo
		err = json.Unmarshal(queryResponse.Value, &bi)
		if err != nil {
			fmt.Println("Unmarshal error.", err)
			ret.Error = "Unmarshal error."
			bytes, _ := json.Marshal(ret)
			return shim.Success(bytes)
		}
		ret.BI = append(ret.BI, bi)
		fmt.Println(bi, '\n')
	}
	if len(ret.BI) == 0 {
		ret.Error = "EmptyBehaviorInfo error."
		fmt.Println("EmptyBehaviorInfo error.")
	} else {
		ret.Error = "OK"
		fmt.Println("OK")
	}
	bytes, _ := json.Marshal(ret)
	return shim.Success(bytes)
}

func main() {
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		fmt.Printf("\n--------------------------------Error starting Simple chaincode: %s--------------------------------\n", err)
	}
}
