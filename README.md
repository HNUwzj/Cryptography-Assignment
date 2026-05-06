# 密码学综合服务系统

## 项目概述

本项目实现了一个密码学核心算法及协议的综合服务系统，采用 **C++** 实现核心加密算法，**Python Flask** 提供 Web 前端服务。

## 功能特性

### 1. 仿射加密
- 支持可配置的密钥参数 a 和 b
- 支持 XML 配置文件输入

仿射加密公式为：

$$
C \equiv a \cdot P + b \pmod{26}
$$

其中 $a$ 与模数 26 必须互素（即 $gcd(a, 26) = 1$），b 为平移量， P 为明文值（通常用 0-25 表示）。

### 2. 流密码
- **RC4**：基于密钥调度的流密码
- **LFSR+J-K触发器**：线性反馈移位寄存器结合J-K触发器

### 3. DES 对称加密
- 标准 DES 加密算法
- 8字节密钥支持

### 4. RSA 非对称加密
- 支持大于 16bit 的消息加密
- 模数规模可配置（默认 1024bit）

### 5. D-H 认证协议及增强 (Anti-MitM)
- **双实体 C/S 网络通信模式**：项目包含严格的两个参与实体。`client.py` 作为客户端发起方，`app.py` 提供 REST API 作为服务端响应方，双方通过真实的 HTTP 网络请求进行通信。
- **消息完整性与来源验证（增强设计）**：基础的 D-H 协议容易受到中间人攻击 (MitM)。本项目采用以下结合设计进行增强：
  - **散列函数 (MD5/SHA-1)**：在传输 D-H 公钥 (Y) 参数前，先对其提取摘要，保证参数如果在网络传输中被篡改能被立刻发现。
  - **数字签名 (RSA)**：发送方使用自己的 RSA 私钥对散列摘要进行签名并随消息发送；接收方收到后，使用对应的 RSA 公钥解密签名进行比对。这不仅验证了消息的完整性，更实现了极强的**来源身份真实性验证**。
- **使用说明**：保持 `app.py` 服务端运行的前提下，新开终端运行 `python client.py`。控制台会完整打印出“生成参数 -> MD5提取摘要 -> RSA签名 -> 网络传输 -> RSA验签 -> 协商出一致的共享密钥”的 7 步攻防交互全过程。

### 6. 散列函数
- SHA-1
- MD5
- **应用场景**：除了在 Web 端提供独立的文本散列计算演示外，在 C/S 架构中负责为 D-H 参数交换提取数字摘要，提供数据防篡改校验。

### 7. 数字签名
- RSA 签名与验证
- **应用场景**：除了在 Web 端的独立演示，核心应用于 D-H 密钥交换过程中，通过“私钥加密摘要、公钥解密摘要”实现实体身份防伪装和来源验证。

## 项目结构

```
test/
├── crypto_core/          # C++ 核心算法
│   ├── crypto_core.h     # 头文件
│   └── crypto_core.cpp   # 实现文件
├── config/               # 配置文件
│   ├── affine_config.xml
│   ├── stream_config.xml
│   ├── des_config.xml
│   └── rsa_config.xml
├── templates/            # Web 模板
│   └── index.html
├── crypto_wrapper.py     # Python ctypes 包装器
├── client.py             # D-H 认证协议独立客户端 (C/S模式)
├── requirements.txt      # Python 依赖清单
├── app.py                # Flask 主程序
└── README.md
```

## 编译 C++ DLL (Windows)

我这里的方法是 g++ 编译成 dll，命令如下，请替换为自己的文件路径：

```bash
cd "D:\密码学实验\Cryptography-Assignment\crypto_core"
g++ -shared -O2 -std=c++11 -DCRYPTO_CORE_EXPORTS -o ..\crypto_core.dll crypto_core.cpp -I"C:\Program Files\OpenSSL-Win64\include" -L"C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD" -lssl -lcrypto -lws2_32 -static-libgcc -static-libstdc++
```

## 运行服务

### 1. 确保已编译 crypto_core.dll 并放置在项目根目录

### 2. 安装 Python 依赖

```bash
pip install -r requirements.txt
```

### 3. 启动服务

```bash
python app.py
```

打开浏览器访问: http://localhost:5000

若是作为服务器运行，则运行 .\start.bat，弹出的 Forwarding 后面跟着的就是公网链接。
## 技术架构

- **前端**: HTML5 + CSS3 + JavaScript (无框架)
- **后端**: Python Flask
- **核心算法**: C++ + OpenSSL
- **通信**: RESTful API (JSON)

## 验收要求

- [x] 加解密综合服务菜单式展示界面 (B/S)
- [x] 仿射加密（密钥可配置）
- [x] 大整数运算（自建 128 位整数类，加、减、乘）
- [x] 流密码（RC4、LFSR+J-K触发器）
- [x] 对称加密（DES）
- [x] 非对称加密（RSA，支持大于16bit消息）
- [x] D-H认证协议（C/S模式）
- [x] 基于 D-H 认证协议的大文件分块加密传输（支持 1G 以上文件）
- [x] 散列函数（SHA-1、MD5）
- [x] 数字签名（RSA）
- [x] 所有基础算法构建在 DLL 中

## 新增功能使用

### 128 位大整数运算

Web 页面左侧菜单选择“128位大整数”，输入两个十进制整数或 `0x` 开头的十六进制整数，点击加法、减法、乘法即可。底层实现位于 `crypto_core/crypto_core.cpp` 的 `UInt128` 自建类，并通过 DLL 导出。

### 1G+ 大文件安全传输

先启动服务端：

```bash
python app.py
```

再运行客户端脚本上传文件：

```bash
python secure_file_client.py D:\path\to\large_file.bin
```

协议流程包括：客户端 RSA 身份签名、D-H 会话密钥协商、服务端 RSA 签名返回、每个文件块 HMAC-SHA256 完整性验证、分块流式加密传输。客户端按块读取文件，适合 1G 以上容量文件，不会一次性加载整个文件。

## 依赖

- OpenSSL (用于 RSA、D-H、SHA、MD5、DES)
- Python 3.7+
- Flask
- MinGW 或 Visual Studio (用于编译 C++ DLL)

