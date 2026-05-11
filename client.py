import argparse
import sys

import requests

try:
    from crypto_wrapper import (
        dh_compute_shared_secret,
        dh_generate_keypair,
        dh_generate_params,
        md5_hash,
        rsa_generate_keys,
        rsa_sign,
        rsa_verify,
    )
except ImportError:
    print("Error: Could not import crypto_wrapper. Make sure crypto_core.dll exists.")
    sys.exit(1)


BASE_URL = "http://127.0.0.1:5000/api"


def short(value, length=24):
    if not value:
        return ""
    return value if len(value) <= length else value[:length] + "..."


def create_test_file(path, size_gb):
    size = int(size_gb * 1024 * 1024 * 1024)
    with open(path, "wb") as f:
        f.truncate(size)
    print(f"created sparse test file: {path} ({size} bytes)")


def upload_large_file(path):
    from secure_file_client import upload_file

    result = upload_file(path, BASE_URL)
    print("=== 大文件安全传输完成 ===")
    print(f"保存路径: {result['saved_path']}")
    print(f"SHA-1: {result['sha1']}")


def demo_dh_auth_exchange():
    print("================ D-H 增强认证通信演示 ================")

    print("\n[Client] 生成 RSA 身份密钥")
    client_rsa_pub, client_rsa_priv = rsa_generate_keys(1024)
    print(f"         Client PublicKey = {client_rsa_pub}")

    p, g = dh_generate_params()
    client_dh_pub, client_dh_priv = dh_generate_keypair(p, g)
    print("\n[Client] 生成 D-H 公钥 Ya")
    print(f"         Ya = {short(client_dh_pub)}")

    client_hash = md5_hash(client_dh_pub)
    print("\n[Client] 对 Ya 做 MD5 摘要")
    print(f"         MD5(Ya) = {client_hash}")

    client_sig = rsa_sign(client_hash, client_rsa_priv)
    print("\n[Client] 用 RSA 私钥签名摘要")
    print(f"         Sign(MD5(Ya)) = {short(client_sig)}")

    payload = {
        "p": p,
        "g": g,
        "client_dh_pub": client_dh_pub,
        "client_rsa_pub": client_rsa_pub,
        "signature": client_sig,
    }
    print("\n[Client -> Server] 发送：")
    print("         p, g, Ya, Client_RSA_PublicKey, Signature")

    response = requests.post(f"{BASE_URL}/dh/auth_exchange", json=payload, timeout=30)
    if response.status_code != 200:
        print("\n[结果] D-H 增强认证通信失败")
        print(f"       Server response: {response.text}")
        return

    data = response.json()
    print("\n[Server] 验证客户端签名")
    print("         RSA_Verify(Client_PublicKey, Signature, MD5(Ya)) = 通过")

    server_dh_pub = data["server_dh_pub"]
    server_rsa_pub = data["server_rsa_pub"]
    server_sig = data["signature"]

    print("\n[Server] 生成 D-H 公钥 Yb")
    print(f"         Yb = {short(server_dh_pub)}")

    server_hash = md5_hash(server_dh_pub)
    print("\n[Server] 对 Yb 做 MD5 摘要并签名")
    print(f"         MD5(Yb) = {server_hash}")
    print(f"         Sign(MD5(Yb)) = {short(server_sig)}")

    print("\n[Server -> Client] 返回：")
    print("         Yb, Server_RSA_PublicKey, Signature")

    server_valid = rsa_verify(server_hash, server_sig, server_rsa_pub)
    print("\n[Client] 验证服务端签名")
    print(f"         RSA_Verify(Server_PublicKey, Signature, MD5(Yb)) = {'通过' if server_valid else '失败'}")
    if not server_valid:
        print("\n[结果] 服务端签名验证失败，通信终止")
        print("=====================================================")
        return

    shared_secret = dh_compute_shared_secret(server_dh_pub, client_dh_priv, p)
    client_preview = shared_secret[:48]
    server_preview = data.get("server_shared_secret_preview", "")

    print("\n[Client] 计算共享密钥")
    print(f"         SharedSecret_Client = {client_preview}...")

    print("\n[Server] 计算共享密钥")
    print(f"         SharedSecret_Server = {server_preview}...")

    if client_preview == server_preview:
        print("\n[结果] 双方共享密钥一致，D-H 增强认证通信成功！")
    else:
        print("\n[结果] 双方共享密钥不一致，D-H 增强认证通信失败！")
    print("=====================================================")


def main():
    parser = argparse.ArgumentParser(description="D-H authenticated communication client")
    parser.add_argument("--file", help="upload a large file with authenticated encrypted chunk transfer")
    parser.add_argument("--make-test-file", help="create a sparse test file for 1G+ transfer demos")
    parser.add_argument("--size-gb", type=float, default=1.1, help="test file size in GB, default: 1.1")
    args = parser.parse_args()

    if args.make_test_file:
        create_test_file(args.make_test_file, args.size_gb)
        return
    if args.file:
        upload_large_file(args.file)
        return

    demo_dh_auth_exchange()


if __name__ == "__main__":
    main()
