# 密码学核心算法及协议综合服务系统

## 项目概述

本项目是“密码学及应用”课程实验系统，实现了一个加解密综合服务平台。系统采用 B/S 架构：核心密码算法由 C++ 实现并编译为 `crypto_core.dll`，Python Flask 提供 Web 页面、REST API 和 C/S 通信服务。

## 功能清单

### 1. 菜单式加解密服务界面

- Web 菜单式界面：`templates/index.html`
- 后端服务：`app.py`
- 浏览器访问：`http://localhost:5000`

### 2. 仿射加密

- 支持加密、解密
- 密钥参数 `a`、`b` 可配置
- 默认配置文件：`config/affine_config.xml`
- 核心实现位于 DLL：`crypto_core/crypto_core.cpp`

加密公式：

```text
C = (a * P + b) mod 26
```

### 3. 128 位大整数运算

- 自建 `UInt128` 类
- 使用 `4 * 32bit` 分段存储 128 位整数
- 支持两个 128 位整数的加法、减法、乘法
- 支持十进制输入和 `0x` 开头的十六进制输入
- DLL 导出函数：
  - `bigint128_add`
  - `bigint128_sub`
  - `bigint128_mul`

### 4. 流密码加密

支持两种密钥流生成方式：

- RC4
- LFSR + J-K 触发器

种子密钥配置文件：

```text
config/stream_config.xml
```

注意：流密码密文是二进制数据，Web 页面以十六进制字符串显示。

### 5. DES 对称加密

- 支持 DES 加密、解密
- 使用 OpenSSL DES 接口
- 默认密钥配置文件：`config/des_config.xml`
- 密文以十六进制字符串显示

### 6. RSA 非对称加密

- 自己构造小模数 RSA
- 模数规模小于 16bit
- 使用逐字节分组加密方式支持大于 16bit 的消息输入
- 密钥每次生成使用随机素数，不再固定
- 配置文件：`config/rsa_config.xml`

### 7. D-H 认证协议及增强通信

系统包含两个参与实体：

- 客户端：`client.py`
- 服务端：`app.py`

通信方式：

- 客户端通过 HTTP 请求访问 Flask 服务端
- 双方使用同一组 D-H 参数 `p, g`
- 客户端发送 `p, g, Ya, Client_RSA_PublicKey, Signature`
- 服务端返回 `Yb, Server_RSA_PublicKey, Signature`

增强设计：

- 使用 MD5 对 D-H 公钥做摘要
- 使用 RSA 对摘要做数字签名
- 接收方使用对方 RSA 公钥验签
- 同时实现消息完整性验证和来源验证

运行演示：

```bash
python app.py
python client.py
```

示例输出格式：

```text
================ D-H 增强认证通信演示 ================

[Client] 生成 RSA 身份密钥
         Client PublicKey = 20567,7

[Client] 生成 D-H 公钥 Ya
         Ya = B6438E7F06DA54B5D45A7334...

[Client] 对 Ya 做 MD5 摘要
         MD5(Ya) = 1b57ad495d75ecbd047bc2556e2cd1dc

[Client] 用 RSA 私钥签名摘要
         Sign(MD5(Ya)) = 4d3e3a994d4d2a101e0c3e30...

[Client -> Server] 发送：
         p, g, Ya, Client_RSA_PublicKey, Signature

[Server] 验证客户端签名
         RSA_Verify(Client_PublicKey, Signature, MD5(Ya)) = 通过

[Server] 生成 D-H 公钥 Yb
         Yb = 1D36B80558894BCE492C47BF...

[Server] 对 Yb 做 MD5 摘要并签名
         MD5(Yb) = 769252fbca4e8b950747c4dc6dcbeb43
         Sign(MD5(Yb)) = 785688f45bf832c60ba495e2...

[Server -> Client] 返回：
         Yb, Server_RSA_PublicKey, Signature

[Client] 验证服务端签名
         RSA_Verify(Server_PublicKey, Signature, MD5(Yb)) = 通过

[Client] 计算共享密钥
         SharedSecret_Client = 6BD6386D3A5D6B4A305036CF47B083A98096FC89BF93112E...

[Server] 计算共享密钥
         SharedSecret_Server = 6BD6386D3A5D6B4A305036CF47B083A98096FC89BF93112E...

[结果] 双方共享密钥一致，D-H 增强认证通信成功！
=====================================================
```

### 8. 1G 以上文件加密传输

服务端接口：

- `/api/secure_file/init`
- `/api/secure_file/chunk`
- `/api/secure_file/finish`

传输设计：

- D-H 协商共享密钥
- RSA 签名验证 D-H 公钥来源
- 每个文件块使用 HMAC-SHA256 做完整性校验
- 文件按 1MB 分块读取、加密、发送
- 不会一次性把整个文件加载到内存，支持 1G 以上文件

完整 1G+ 测试流程如下。

第一步，启动 Flask 服务端：

```bash
python app.py
```

第二步，生成 1G 以上测试文件。下面命令会创建一个约 1.1GB 的稀疏测试文件：

```bash
python client.py --make-test-file test_1g.bin --size-gb 1.1
```

第三步，确认测试文件大小：

```powershell
(Get-Item test_1g.bin).Length
```

输出应约为：

```text
1181116006
```

第四步，执行安全加密传输：

```bash
python client.py --file test_1g.bin
```

客户端会按 1MB 分块输出发送进度，例如：

```text
sent 1048576/1181116006 bytes
...
sent 1181116006/1181116006 bytes
=== 大文件安全传输完成 ===
保存路径: D:\密码学实验\Cryptography-Assignment\received_files\xxxx_test_1g.bin
SHA-1: 27d89fefa2cd62def47d8c3b3c3818701a4d66fc
```

第五步，检查服务端接收文件大小。将下面命令里的文件名替换为客户端输出的实际保存文件名：

```powershell
(Get-Item received_files\xxxx_test_1g.bin).Length
```

该值应与原始 `test_1g.bin` 完全一致。

第六步，对比原始文件和接收文件的 SHA-1：

```powershell
Get-FileHash test_1g.bin -Algorithm SHA1
Get-FileHash received_files\xxxx_test_1g.bin -Algorithm SHA1
```

两个 SHA-1 值完全一致，即可证明 1G 以上文件已经完成分块加密传输、服务端接收、解密和完整性验证。

测试完成后可清理测试文件：

```powershell
Remove-Item test_1g.bin
Remove-Item received_files\xxxx_test_1g.bin
```

### 9. 散列函数与数字签名

支持：

- MD5
- SHA-1
- RSA 签名
- RSA 验签

这些功能既可以在 Web 页面单独演示，也用于 D-H 增强认证协议。

## 项目结构

```text
Cryptography-Assignment/
├── app.py                    # Flask Web 服务端
├── client.py                 # D-H 认证通信与大文件传输客户端
├── secure_file_client.py     # 大文件安全传输实现
├── crypto_wrapper.py         # Python ctypes DLL 包装层
├── crypto_core.dll           # C++ 核心算法 DLL
├── crypto_core/
│   ├── crypto_core.h         # DLL 导出接口
│   └── crypto_core.cpp       # 核心算法实现
├── config/
│   ├── affine_config.xml     # 仿射加密配置
│   ├── stream_config.xml     # 流密码配置
│   ├── des_config.xml        # DES 配置
│   └── rsa_config.xml        # RSA 配置
├── templates/
│   └── index.html            # Web 页面
├── requirements.txt
├── start.bat
└── README.md
```

## 编译 C++ DLL

Windows + MinGW 示例：

```bash
cd "D:\密码学实验\Cryptography-Assignment\crypto_core"
g++ -shared -O2 -std=c++11 -DCRYPTO_CORE_EXPORTS -o ..\crypto_core.dll crypto_core.cpp -I"C:\Program Files\OpenSSL-Win64\include" -L"C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD" -lssl -lcrypto -lws2_32 -static-libgcc -static-libstdc++
```

如果 `crypto_core.dll` 正在被 Flask/Python 占用，请先停止服务后再重新编译。

## 运行方式

安装依赖：

```bash
pip install -r requirements.txt
```

启动 Web 服务：

```bash
python app.py
```

访问：

```text
http://localhost:5000
```

运行 D-H 增强认证通信演示：

```bash
python client.py
```

运行大文件安全传输：

```bash
python client.py --file D:\path\to\large_file.bin
```

## 验收对照

- [x] 加解密综合服务菜单式展示界面
- [x] 仿射加密，密钥支持 XML 配置
- [x] 128 位大整数加、减、乘运算，自建类实现
- [x] 流密码 RC4
- [x] 流密码 LFSR + J-K 触发器
- [x] 流密码种子密钥支持 XML 配置
- [x] DES 对称加密，密钥支持 XML 配置
- [x] RSA 非对称加密，自构造小模数，支持长消息输入
- [x] D-H 认证协议，两个参与实体，真实网络通信
- [x] MD5/SHA-1 摘要
- [x] RSA 数字签名和验签
- [x] 消息完整性验证和来源验证
- [x] 1G 以上文件分块加密传输
- [x] 基础算法构建在 DLL 中

## 依赖

- Python 3.7+
- Flask
- requests
- OpenSSL
- MinGW 或 Visual Studio C++ 编译工具
