// main.go
package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

func execCommands(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.Output()
}

func main() {
	fmt.Println("program start:", time.Now())

	// 1) 如果已持久化激活，最好再次校验其有效期
	if isActivated() {
		fmt.Println("already activated")
		return
	}

	// 2) 否则，请求用户提供 token 文件路径（示例）
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <token.json>\n", os.Args[0])
		fmt.Println("No token file provided. Exiting.")
		return
	}
	tokenPath := os.Args[1]
	if err := verifyTokenFile(tokenPath); err != nil {
		fmt.Println("activation failed:", err)
		return
	}
	fmt.Println("activation success")
}
