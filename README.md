# 离线激活示例文档

## 一、原理
- 服务端（签名器）signer.go：用私钥对 {machine_id, program_hash, expiry} 生成离线激活令牌（JSON + Base64(RSA-PSS-SIG)）
- 客户端/程序端（激活库 + 示例）activator.go + main.go：内嵌公钥，程序启动时计算自身二进制哈希、读取本机 machine id，解析/验签激活令牌，做完整性与设备绑定检测，并把激活结果持久化到本地文件（示例实现）

## 二、使用步骤
### 1）准备工作目录与示例代码
在终端创建分别创建客户端和服务端项目文件夹：
```bash
# 创建服务端项目文件夹
mkdir ~/offline-activate/client-side

# 创建客户端项目文件夹
mkdir ~/offline-activate/server-side
```

把源代码分别放入以上两个项目，项目结构如下：
```bash
offline-activate/
        ├──────client-side/   # 客户端
        │          ├───────── main.go  # 客户端示例入口
        │          └───────── activator.go  # 客户端激活库
        └──────server-client/   # 服务端
                     └───────── signer.go  # 签发端
```

### 2）生成 RSA 密钥对（私钥/公钥）
在 server-client/ 下执行（2048-bit 示例）：
```bash
# 生成私钥（PKCS#8 格式）
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048

# 从私钥导出公钥（PEM 格式）
openssl rsa -pubout -in private.pem -out public.pem
```
>说明：private.pem 请严格保密，只放在签名器/管理员机器上。public.pem 会嵌入客户端程序

### 3）编译签名器（signer）
在 server-client/ 下运行：
```bash
go build -o signer signer.go
```

测试 help：
```bash
./signer -h
```

### 4）计算客户端二进制的 SHA256(program_hash)
#### 4.1 先把 activator.go 中 pubKeyPEM 填成占位（或任意现成 public.pem 内容）
例如编辑 activator.go，把
```go
const pubKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...
-----END PUBLIC KEY-----`
```
替换为你刚生成的 public.pem 的全部内容（包含 BEGIN/END 行）

#### 4.2 编译客户端临时二进制（用于计算 hash）
```go
go build -o myprogram main.go activator.go
```

#### 4.3 计算 SHA256（在 macOS / Linux）
```bash
# Linux:
sha256sum myprogram | awk '{print $1}'

# macOS:
shasum -a 256 myprogram | awk '{print $1}'
```

将输出的 hex 字符串复制，作为 program_hash。
>Windows 请用： certutil -hashfile myprogram SHA256 并取输出的哈希值（去掉空格）。

### 5）用签名器生成 token.json（签发激活令牌）
假设你要给机器 ID MACHINE-1234 授权，过期时间到 2026-12-31T23:59:59Z，并且 program_hash 如上取得。

执行：
```bash
./signer -private private.pem -machine-id MACHINE-1234 -program-hash f7c3bc1d808e04732adf679965ccc34ca7ae3441d9e8a3d6b0f... -expiry 2026-12-31T23:59:59Z -out token.json
```

生成后查看：
```bash
cat token.json
```

应该看到类似：
```json
{
  "machine_id": "MACHINE-1234",
  "program_hash": "f7c3bc1d808e0...",
  "expiry": "2026-12-31T23:59:59Z",
  "extra": "",
  "signature": "BASE64..."
}
```
你可以把 token.json 用 USB、二维码或其它离线方式交给被授权机器。

### 6）在被授权机器上运行激活（客户端）
将 myprogram 和 token.json 放到被授权机器上（同目录），运行：
```bash
./myprogram token.json
```

输出示例：
```bash
program start: 2025-09-27 10:00:00
activation success
```
>若失败，会打印失败原因（如：signature verify failed、token expired、machine id mismatch、program hash mismatch 等），根据信息排查。

## 三、注意事项
### 1）关于激活文件
在程序启动时或激活时会先检测是否已激活，检测的方式是检查某个激活文件是否存在，可以通过手动复制一个加的激活文件到指定路径，从而绕过验证。为了避免这种情况，离线激活机制必须做到以下几点：

**1. 激活文件不可伪造**
- 激活文件必须包含数字签名（由开发者私钥签名）。
- 程序里内置开发者的公钥，启动时用公钥验证签名。
- 这样用户即使手动拷贝一个文件，没有正确签名也无法通过验证。

**2. 绑定机器环境**
- 激活文件里要包含「机器码」(如 CPU ID、硬盘序列号、MAC 地址等)。
- 程序验证时重新计算本机机器码，和激活文件中的值比对。
- 即使别人把激活文件拷贝到另一台机器，也不能通过验证。

**3. 绑定程序完整性（可选加强）**
- 在激活文件中包含开发者计算好的 程序二进制的 hash。
- 程序运行时自检自身的二进制 hash，和激活文件里的值比对。
- 这样可以防止二进制被篡改后绕过验证。

## 四、参考方案
- https://github.com/wpvsyou/oflauth?tab=readme-ov-file