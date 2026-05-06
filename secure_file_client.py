import argparse
import hashlib
import hmac
import os
from pathlib import Path

import requests

from crypto_wrapper import (
    dh_compute_shared_secret,
    dh_generate_keypair,
    dh_generate_params,
    md5_hash,
    rsa_generate_keys,
    rsa_sign,
    rsa_verify,
)


BASE_URL = "http://127.0.0.1:5000/api"
DEFAULT_CHUNK_SIZE = 1024 * 1024


def session_key(shared_secret):
    return hashlib.sha256(shared_secret.encode()).digest()


def xor_stream(data, key, chunk_index):
    out = bytearray(len(data))
    offset = 0
    counter = 0
    while offset < len(data):
        seed = key + chunk_index.to_bytes(8, "big") + counter.to_bytes(8, "big")
        block = hashlib.sha256(seed).digest()
        take = min(len(block), len(data) - offset)
        for i in range(take):
            out[offset + i] = data[offset + i] ^ block[i]
        offset += take
        counter += 1
    return bytes(out)


def upload_file(path, base_url=BASE_URL):
    source = Path(path)
    if not source.exists() or not source.is_file():
        raise FileNotFoundError(source)

    client_rsa_pub, client_rsa_priv = rsa_generate_keys(1024)
    p, g = dh_generate_params()
    client_dh_pub, client_dh_priv = dh_generate_keypair(p, g)
    signature = rsa_sign(md5_hash(client_dh_pub), client_rsa_priv)

    init_payload = {
        "client_dh_pub": client_dh_pub,
        "client_rsa_pub": client_rsa_pub,
        "signature": signature,
        "p": p,
        "g": g,
        "filename": source.name,
        "size": source.stat().st_size,
    }
    init_resp = requests.post(f"{base_url}/secure_file/init", json=init_payload, timeout=30)
    init_resp.raise_for_status()
    init_data = init_resp.json()

    server_hash = md5_hash(init_data["server_dh_pub"])
    if not rsa_verify(server_hash, init_data["signature"], init_data["server_rsa_pub"]):
        raise RuntimeError("server signature verification failed")

    shared_secret = dh_compute_shared_secret(init_data["server_dh_pub"], client_dh_priv, p)
    key = session_key(shared_secret)
    chunk_size = int(init_data.get("chunk_size", DEFAULT_CHUNK_SIZE))
    session_id = init_data["session_id"]

    sha1 = hashlib.sha1()
    sent = 0
    total = source.stat().st_size
    with source.open("rb") as f:
        for chunk_index, chunk in enumerate(iter(lambda: f.read(chunk_size), b"")):
            sha1.update(chunk)
            encrypted = xor_stream(chunk, key, chunk_index)
            mac = hmac.new(
                key,
                chunk_index.to_bytes(8, "big") + encrypted,
                hashlib.sha256,
            ).hexdigest()
            headers = {
                "X-Session-Id": session_id,
                "X-Chunk-Index": str(chunk_index),
                "X-Chunk-Mac": mac,
                "Content-Type": "application/octet-stream",
            }
            resp = requests.post(
                f"{base_url}/secure_file/chunk",
                headers=headers,
                data=encrypted,
                timeout=120,
            )
            resp.raise_for_status()
            sent += len(chunk)
            print(f"sent {sent}/{total} bytes")

    finish_resp = requests.post(
        f"{base_url}/secure_file/finish",
        json={"session_id": session_id, "sha1": sha1.hexdigest()},
        timeout=30,
    )
    finish_resp.raise_for_status()
    return finish_resp.json()


def main():
    parser = argparse.ArgumentParser(description="Authenticated D-H encrypted file uploader")
    parser.add_argument("file", help="file path to upload; supports very large files by streaming chunks")
    parser.add_argument("--base-url", default=BASE_URL, help="server API base URL")
    args = parser.parse_args()

    result = upload_file(args.file, args.base_url)
    print("upload ok")
    print(f"saved_path: {result['saved_path']}")
    print(f"sha1: {result['sha1']}")


if __name__ == "__main__":
    main()
