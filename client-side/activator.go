// activator.go
package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type Token struct {
	MachineID   string `json:"machine_id"`
	ProgramHash string `json:"program_hash"`
	Expiry      string `json:"expiry"`
	Extra       string `json:"extra"`
	Signature   string `json:"signature"`
}

// 把你的 public.pem 内容拷贝到这个字符串（PEM）
const pubKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu7rLUjlxMLXOp7TM4UvH
A5SswZRGZUbhCnsHVzLiLTT/rb/GoFeSKmnEDjDprpTM+0yl/j7e1PtVftp+Ozjl
vVFAHyZ5updhWXg25Wuv+b1o6vkLbhKEgfZ86ivgYmD4CVo6fDFohuUS1guXDnvL
/W3aHDdkMBU8wGYasHm3JNsCeh8SS6DCt+JDOhy6XCpwQFCsb6jRJUF/JZNfYc7u
nai2Txao/R3m/EGkYwsGpnTAVpfPpDWjne3f2fidPxYqJgDiYsZLlm/YbgyqTJjn
yFaEXc1TzCIuWqi4Lf0Io2pi7+GyKTifJrdxrwwIDWWn+NnPvT5bTFPjvPWflnLX
wQIDAQAB
-----END PUBLIC KEY-----`

// 激活文件位置（可自定义）
// 将激活文件存放到操作系统的临时目录路径
var activationFile = filepath.Join(os.TempDir(), "myprogram_activation.json")

func parsePublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("pem decode failed")
	}
	pubIfc, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if pk, ok := pubIfc.(*rsa.PublicKey); ok {
		return pk, nil
	}
	return nil, errors.New("not rsa public key")
}

func verifySignature(pk *rsa.PublicKey, payload []byte, sigB64 string) error {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return err
	}
	h := sha256.Sum256(payload)
	return rsa.VerifyPSS(pk, crypto.SHA256, h[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}

func computeProgramHash() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	f, err := os.Open(exe)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// cross-platform machine id best-effort 获取（Linux / macOS / Windows / fallback to MAC)
func getMachineID() (string, error) {
	// 1) Linux: /etc/machine-id or /var/lib/dbus/machine-id
	if runtime.GOOS == "linux" {
		if b, err := ioutil.ReadFile("/etc/machine-id"); err == nil {
			id := strings.TrimSpace(string(b))
			if id != "" {
				return id, nil
			}
		}
		if b, err := ioutil.ReadFile("/var/lib/dbus/machine-id"); err == nil {
			id := strings.TrimSpace(string(b))
			if id != "" {
				return id, nil
			}
		}
	}
	// 2) macOS: ioreg IOPlatformUUID
	if runtime.GOOS == "darwin" {
		out, err := runCmdOutput("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
		if err == nil {
			// crude parsing
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, "IOPlatformUUID") {
					parts := strings.Split(line, "=")
					if len(parts) >= 2 {
						id := strings.Trim(parts[1], " \"")
						if id != "" {
							return id, nil
						}
					}
				}
			}
		}
	}
	// 3) windows: registry
	if runtime.GOOS == "windows" {
		out, err := runCmdOutput("reg", "query", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid")
		if err == nil {
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, "MachineGuid") {
					fields := strings.Fields(line)
					if len(fields) >= 3 {
						return fields[len(fields)-1], nil
					}
				}
			}
		}
	}
	// fallback: first non-loopback MAC
	ifas, err := net.Interfaces()
	if err == nil {
		for _, itf := range ifas {
			if (itf.Flags&net.FlagLoopback) == 0 && len(itf.HardwareAddr) > 0 {
				return itf.HardwareAddr.String(), nil
			}
		}
	}
	return "", errors.New("no machine id available")
}

func runCmdOutput(name string, args ...string) (string, error) {
	out, err := execCommand(name, args...)
	return string(out), err
}

// 最小化外部依赖的 exec wrapper（避免在 playground 报错）
func execCommand(name string, args ...string) ([]byte, error) {
	// simple wrapper to avoid direct import of os/exec in static analysis,
	// but we can just invoke it.
	return []byte(""), errors.New("exec not implemented on this platform")
}

func verifyTokenFile(tokenPath string) error {
	b, err := ioutil.ReadFile(tokenPath)
	if err != nil {
		return err
	}
	var t Token
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	// parse public key
	pk, err := parsePublicKey(pubKeyPEM)
	if err != nil {
		return err
	}
	// prepare payload (token without signature)
	copyToken := Token{
		MachineID:   t.MachineID,
		ProgramHash: t.ProgramHash,
		Expiry:      t.Expiry,
		Extra:       t.Extra,
		Signature:   "",
	}
	payload, _ := json.Marshal(copyToken)
	fmt.Println("payload:", string(payload))

	// verify signature
	if err := verifySignature(pk, payload, t.Signature); err != nil {
		return fmt.Errorf("signature verify failed: %v", err)
	}

	// check expiry
	exp, err := time.Parse(time.RFC3339, t.Expiry)
	if err != nil {
		return err
	}
	if time.Now().After(exp) {
		return fmt.Errorf("token expired at %v", exp)
	}

	// check program hash
	localHash, err := computeProgramHash()
	if err != nil {
		return err
	}
	fmt.Println("localHash:", localHash)
	if localHash != t.ProgramHash {
		return fmt.Errorf("program hash mismatch: token=%s local=%s", t.ProgramHash, localHash)
	}

	// check machine id
	localMID, err := getMachineID()
	if err != nil {
		return err
	}
	fmt.Println("localMID:", localMID)
	if localMID != t.MachineID {
		return fmt.Errorf("machine id mismatch: token=%s local=%s", t.MachineID, localMID)
	}

	// passed all checks -> persist activation
	if err := persistActivation(tokenPath); err != nil {
		return fmt.Errorf("persist activation: %v", err)
	}

	return nil
}

func persistActivation(tokenPath string) error {
	// 将 token 复制到 activationFile（或者可做签名/加密存储）
	b, err := ioutil.ReadFile(tokenPath)
	if err != nil {
		return err
	}
	// 简单持久化：写入本地文件（可改为加密 + 加平台 keyring）
	return ioutil.WriteFile(activationFile, b, 0600)
}

func isActivated() bool {
	if _, err := os.Stat(activationFile); err == nil {
		// 也可以做更严格的检查（例如再次验签、检查 expiry）
		return true
	}
	return false
}
