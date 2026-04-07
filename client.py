import requests
import json
import os
import sys

# 尝试导入我们自己本地打包的加密库，因为客户端也要做本地的密码学计算
try:
    from crypto_wrapper import (
        rsa_generate_keys, rsa_sign, rsa_verify,
        dh_generate_params, dh_generate_keypair, dh_compute_shared_secret,
        md5_hash, sha1_hash
    )
except ImportError as e:
    print("Error: Could not import crypto_wrapper. Make sure crypto_core.dll exists.")
    sys.exit(1)

BASE_URL = "http://127.0.0.1:5000/api"

def main():
    print("=" * 60)
    print(" 增强型 D-H 认证协议客户端 (Anti-MitM) 测试与通信演示 ")
    print("=" * 60)

    # 1. 客户端本地生成 RSA 身份密钥
    print("[1] 客户端正在生成自己的 RSA 身份公私钥对...")
    c_rsa_pub, c_rsa_priv = rsa_generate_keys(1024)
    print(f"    - 公钥: {c_rsa_pub}")
    
    # 2. 客户端获取系统 D-H 全局参数 (也可以通过向服务端请求)
    print("\n[2] 获取全局防篡改 D-H 参数...")
    # 为了演示，客户端可以请求系统全局参数
    resp = requests.post(f"{BASE_URL}/dh/generate_params")
    if resp.status_code != 200:
        print("    ! 无法连接服务端，是否启动了 Flask APP?")
        return
        
    p = resp.json()['p']
    g = resp.json()['g']
    
    # 3. 客户端生成本次会话的 D-H 密钥对的 Y_A 
    print("\n[3] 客户端生成本次会话的 D-H 公私钥对 (Y_a, X_a)...")
    c_dh_pub, c_dh_priv = dh_generate_keypair(p, g)
    
    # 4. 增强安全：为了防篡改（中间人攻击），使用散列算法对消息摘要并签名
    print("\n[4] 客户端使用 MD5 对 D-H 公钥 Y_a 进行散列，并用 RSA 私钥进行签名：完整性验证与身份证明")
    c_hash = md5_hash(c_dh_pub)
    c_sig = rsa_sign(c_hash, c_rsa_priv)
    
    payload = {
        'client_dh_pub': c_dh_pub,
        'client_rsa_pub': c_rsa_pub,
        'signature': c_sig
    }

    # 5. 发送至服务端
    print("\n[5] 正向服务端发送带有签名的 D-H 密钥交换请求...")
    auth_resp = requests.post(f"{BASE_URL}/dh/auth_exchange", json=payload)
    
    if auth_resp.status_code != 200:
        print(f"    ! 认证失败或发生内部错误: {auth_resp.text}")
        return
        
    s_data = auth_resp.json()
    print("    => 交换成功！服务端已成功验证我的身份，并返回了服务端的 Y_b 和签名。")
    
    s_dh_pub = s_data['server_dh_pub']
    s_rsa_pub = s_data['server_rsa_pub']
    s_sig = s_data['signature']
    
    # 6. 验证服务端的签名
    print("\n[6] 客户端验证服务端返回的数据签名，确保来源是真实的 Server 且数据未被篡改...")
    s_hash = md5_hash(s_dh_pub)
    is_valid = rsa_verify(s_hash, s_sig, s_rsa_pub)
    
    if is_valid:
        print("    => 验证通过！服务端的源是可信的, 消息完整！")
    else:
        print("    !! 严重安全警告：验证失败！检测到中间人攻击或数据损坏！")
        return
        
    # 7. 生成最终的会话密钥
    print("\n[7] 双方验证通过！客户端开始计算最终的协商共享密钥 (Shared Secret)...")
    shared_secret = dh_compute_shared_secret(s_dh_pub, c_dh_priv, p)
    print(f"\n[最终协商密钥] (截断展示):\n    {shared_secret[:48]}......\n")
    print("=== D-H 通信协议演示完成！ ===")

if __name__ == "__main__":
    main()
