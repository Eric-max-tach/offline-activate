// # 生成 2048-bit 私钥（PEM）
//openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
//
//# 从私钥导出公钥（PEM）
//openssl rsa -pubout -in private.pem -out public.pem

// 用法示例： go run signer.go -private private.pem -machine-id 82:ff:d9:2d:e2:dd -expiry 2026-12-31T23:59:59Z -program-hash 856106cbbc7cac9da7debebce1a86b6892764eb2049faa942bfee174d3b3515f
// 或者：./signer -private private.pem -machine-id 82:ff:d9:2d:e2:dd -expiry 2026-12-31T23:59:59Z -program-hash 856106cbbc7cac9da7debebce1a86b6892764eb2049faa942bfee174d3b3515f
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

type Token struct {
	MachineID   string `json:"machine_id"`
	ProgramHash string `json:"program_hash"`
	Expiry      string `json:"expiry"`    // RFC3339
	Extra       string `json:"extra"`     // 可拓展字段
	Signature   string `json:"signature"` // Base64 签名
}

// 加载 RSA 私钥
func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("Failed to decode PEM block")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if k, ok := priv.(*rsa.PrivateKey); ok {
			return k, nil
		}
	}

	// 回退尝试 PKCS1
	if pk, err2 := x509.ParsePKCS1PrivateKey(block.Bytes); err2 == nil {
		return pk, nil
	}
	return nil, fmt.Errorf("parse private key failed: %v", err)
}

// 对 payload（包含 machine_id, program_hash, expiry, extra 的 JSON bytes）整体进行 PSS 签名（PSS 签名是 RSA 算法的拓展）
// 对生成的签名 sig 进行 Base64 编码，填充到 Token 的 signature 字段
func signToekn(priv *rsa.PrivateKey, payload []byte) (string, error) {
	h := sha256.Sum256(payload)
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

func main() {
	// 解析命令行参数，例如“flag.String("private", "private.pem", "PEM private key path")”中
	// 第一个参数 "private"：是该标志的名称，用户通过命令行输入时会使用这个名称来指定该参数的值
	// 第二个参数 "private.pem"：是该标志的默认值。如果用户没有通过命令行输入该标志，它将使用这个默认值
	// 第三个参数 "PEM private key path"：是该标志的描述，通常用于帮助信息中，向用户解释这个参数的作用
	// go run main.go -private=my_key.pem
	// 输出: Private key path: my_key.pem
	privPath := flag.String("private", "private.pem", "PEM private key path")
	machineID := flag.String("machine-id", "", "machine id to bind")
	programHash := flag.String("program-hash", "", "program binary sha256 hex")
	expiryStr := flag.String("expiry", "", "expiry ISO8601 (e.g. 2026-12-31T23:59:59Z)")
	extra := flag.String("extra", "", "extra data")
	out := flag.String("out", "token.json", "output token file")
	flag.Parse()

	fmt.Println("machine id:", *machineID)
	fmt.Println("program hash:", *programHash)
	fmt.Println("expiry:", *expiryStr)
	if *machineID == "" || *programHash == "" || *expiryStr == "" {
		fmt.Println("machine-id, program-hash and expiry are required")
		flag.Usage()
		os.Exit(1)
	}

	priv, err := loadPrivateKey(*privPath)
	if err != nil {
		fmt.Println("Failed to load private key:", err)
		os.Exit(1)
	}

	// 构造要签的 payload（不含 siguature 字段）
	t := Token{
		MachineID:   *machineID,
		ProgramHash: *programHash,
		Expiry:      *expiryStr,
		Extra:       *extra,
	}
	payload, _ := json.Marshal(t)

	sig, err := signToekn(priv, payload)
	if err != nil {
		fmt.Println("sign failed:", err)
		os.Exit(1)
	}

	t.Signature = sig
	outb, _ := json.MarshalIndent(t, "", "  ")
	if err := ioutil.WriteFile(*out, outb, 0644); err != nil {
		fmt.Println("write out:", err)
		os.Exit(1)
	}
	fmt.Println("token written to", *out)
}
