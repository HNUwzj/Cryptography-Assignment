"""
密码学综合服务系统 - Flask 前端
"""
from flask import Flask, render_template, request, jsonify, session
import os
import sys

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)
app.secret_key = 'crypto-lab-secret-key-2024'

# 尝试导入加密库
crypto_available = False
try:
    import crypto_wrapper as _crypto_wrapper
    from crypto_wrapper import (
        affine_encrypt, affine_decrypt,
        rc4_init, rc4_encrypt, rc4_decrypt,
        lfsr_jk_init, lfsr_jk_encrypt, lfsr_jk_decrypt,
        des_encrypt, des_decrypt,
        rsa_generate_keys, rsa_encrypt, rsa_decrypt,
        rsa_sign, rsa_verify,
        dh_generate_params, dh_generate_keypair, dh_compute_shared_secret,
        sha1_hash, md5_hash
    )
    crypto_available = _crypto_wrapper.lib is not None
except Exception as e:
    print(f"Crypto library not available: {e}")

@app.route('/')
def index():
    return render_template('index.html', crypto_available=crypto_available)

# ==================== 仿射加密 ====================
@app.route('/api/affine/encrypt', methods=['POST'])
def api_affine_encrypt():
    data = request.json
    plaintext = data.get('plaintext', '')
    key_a = int(data.get('key_a', 5))
    key_b = int(data.get('key_b', 8))

    if not crypto_available:
        return jsonify({'error': 'Crypto library not loaded'}), 500

    try:
        ciphertext = affine_encrypt(plaintext, key_a, key_b)
        return jsonify({'ciphertext': ciphertext})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/affine/decrypt', methods=['POST'])
def api_affine_decrypt():
    data = request.json
    ciphertext = data.get('ciphertext', '')
    key_a = int(data.get('key_a', 5))
    key_b = int(data.get('key_b', 8))

    if not crypto_available:
        return jsonify({'error': 'Crypto library not loaded'}), 500

    try:
        plaintext = affine_decrypt(ciphertext, key_a, key_b)
        return jsonify({'plaintext': plaintext})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== RC4 流密码 ====================
@app.route('/api/rc4/encrypt', methods=['POST'])
def api_rc4_encrypt():
    data = request.json
    plaintext = data.get('plaintext', '')
    key = data.get('key', '')

    if not crypto_available:
        return jsonify({'error': 'Crypto library not loaded'}), 500

    try:
        rc4_init(key.encode())
        ciphertext = rc4_encrypt(plaintext.encode()).hex()
        return jsonify({'ciphertext': ciphertext})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rc4/decrypt', methods=['POST'])
def api_rc4_decrypt():
    data = request.json
    ciphertext_hex = data.get('ciphertext', '')
    key = data.get('key', '')

    if not crypto_available:
        return jsonify({'error': 'Crypto library not loaded'}), 500

    try:
        ciphertext = bytes.fromhex(ciphertext_hex)
        rc4_init(key.encode())
        plaintext = rc4_decrypt(ciphertext).decode()
        return jsonify({'plaintext': plaintext})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== LFSR + J-K 触发器 ====================
@app.route('/api/lfsr_jk/encrypt', methods=['POST'])
def api_lfsr_jk_encrypt():
    data = request.json
    plaintext = data.get('plaintext', '')
    seed = data.get('seed', '')

    if not crypto_available:
        return jsonify({'error': 'Crypto library not loaded'}), 500

    try:
        lfsr_jk_init(seed.encode())
        ciphertext = lfsr_jk_encrypt(plaintext.encode()).hex()
        return jsonify({'ciphertext': ciphertext})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/lfsr_jk/decrypt', methods=['POST'])
def api_lfsr_jk_decrypt():
    data = request.json
    ciphertext_hex = data.get('ciphertext', '')
    seed = data.get('seed', '')

    if not crypto_available:
        return jsonify({'error': 'Crypto library not loaded'}), 500

    try:
        ciphertext = bytes.fromhex(ciphertext_hex)
        lfsr_jk_init(seed.encode())
        plaintext = lfsr_jk_decrypt(ciphertext).decode()
        return jsonify({'plaintext': plaintext})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== DES 对称加密 ====================
@app.route('/api/des/encrypt', methods=['POST'])
def api_des_encrypt():
    data = request.json
    plaintext = data.get('plaintext', '')
    key = data.get('key', '')

    if not crypto_available:
        return jsonify({'error': 'Crypto library not loaded'}), 500

    try:
        ciphertext = des_encrypt(plaintext, key)
        return jsonify({'ciphertext': ciphertext})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/des/decrypt', methods=['POST'])
def api_des_decrypt():
    data = request.json
    ciphertext_hex = data.get('ciphertext', '')
    key = data.get('key', '')

    if not crypto_available:
        return jsonify({'error': 'Crypto core not available'}), 500

    try:
        plaintext = des_decrypt(ciphertext_hex, key)
        return jsonify({'plaintext': plaintext})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== RSA 非对称加密 ====================
@app.route('/api/rsa/generate_keys', methods=['POST'])
def api_rsa_generate_keys():
    if not crypto_available:
        return jsonify({'error': 'Crypto library not loaded'}), 500

    try:
        public_key, private_key = rsa_generate_keys(1024)
        return jsonify({'public_key': public_key, 'private_key': private_key})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rsa/encrypt', methods=['POST'])
def api_rsa_encrypt():
    data = request.json
    plaintext = data.get('plaintext', '')
    public_key = data.get('public_key', '')

    if not crypto_available:
        return jsonify({'error': 'Crypto library not loaded'}), 500

    try:
        # RSA 加密限制：消息长度不能超过密钥长度
        ciphertext = rsa_encrypt(plaintext, public_key)
        return jsonify({'ciphertext': ciphertext})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rsa/decrypt', methods=['POST'])
def api_rsa_decrypt():
    data = request.json
    ciphertext = data.get('ciphertext', '')
    private_key = data.get('private_key', '')

    if not crypto_available:
        return jsonify({'error': 'Crypto library not loaded'}), 500

    try:
        plaintext = rsa_decrypt(ciphertext, private_key)
        return jsonify({'plaintext': plaintext})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== RSA 数字签名 ====================
@app.route('/api/rsa/sign', methods=['POST'])
def api_rsa_sign():
    data = request.json
    message = data.get('message', '')
    private_key = data.get('private_key', '')

    if not crypto_available:
        return jsonify({'error': 'Crypto library not loaded'}), 500

    try:
        signature = rsa_sign(message, private_key)
        return jsonify({'signature': signature})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rsa/verify', methods=['POST'])
def api_rsa_verify():
    data = request.json
    message = data.get('message', '')
    signature = data.get('signature', '')
    public_key = data.get('public_key', '')

    if not crypto_available:
        return jsonify({'error': 'Crypto library not loaded'}), 500

    try:
        valid = rsa_verify(message, signature, public_key)
        return jsonify({'valid': valid})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== D-H 密钥交换 ====================
@app.route('/api/dh/generate_params', methods=['POST'])
def api_dh_generate_params():
    if not crypto_available:
        return jsonify({'error': 'Crypto library not loaded'}), 500

    try:
        p, g = dh_generate_params()
        return jsonify({'p': p, 'g': g})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dh/generate_keypair', methods=['POST'])
def api_dh_generate_keypair():
    data = request.json
    p = data.get('p', '')
    g = data.get('g', '')

    if not crypto_available:
        return jsonify({'error': 'Crypto library not loaded'}), 500

    try:
        public_key, private_key = dh_generate_keypair(p, g)
        return jsonify({'public_key': public_key, 'private_key': private_key})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dh/compute_secret', methods=['POST'])
def api_dh_compute_secret():
    data = request.json
    public_key = data.get('public_key', '')
    private_key = data.get('private_key', '')
    p = data.get('p', '')

    if not crypto_available:
        return jsonify({'error': 'Crypto library not loaded'}), 500

    try:
        shared_secret = dh_compute_shared_secret(public_key, private_key, p)
        return jsonify({'shared_secret': shared_secret})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== D-H 认证协议及增强 (C/S 架构网络通信) ====================
# 服务端持有的身份密钥（在实际中应该是固定的，这里用懒加载模式生成）
server_rsa_keys = {}

@app.route('/api/dh/auth_exchange', methods=['POST'])
def api_dh_auth_exchange():
    """
    客户端发来:
    - client_dh_pub: 客户端的 D-H 公钥 (Y_A)
    - client_rsa_pub: 客户端的 RSA 公钥 (其实应由PKI分配，这是简化的模拟)
    - signature: 客户端对 Y_A 取 MD5 后的 RSA 签名消息
    - p, g: 服务端使用的校验参数
    """
    if not crypto_available:
        return jsonify({'error': 'Crypto library not loaded'}), 500
        
    data = request.json
    client_dh_pub = data.get('client_dh_pub')
    client_rsa_pub = data.get('client_rsa_pub')
    signature = data.get('signature')
    
    try:
        # 1. 验证客户端来源与完整性
        # 通过 MD5 取出验证散列 (也可直接对消息签名，这里演示散列+签名)
        client_hash = md5_hash(client_dh_pub)
        is_valid = rsa_verify(client_hash, signature, client_rsa_pub)
        
        if not is_valid:
            return jsonify({'error': 'Signature verification failed! Possible Man-in-the-Middle attack.'}), 403
            
        # 2. 服务端生成自己的 D-H 密钥对 
        p, g = dh_generate_params()
        server_dh_pub, server_dh_priv = dh_generate_keypair(p, g)
        
        # 3. 服务端配置自己的 RSA 身份 (如果还没有)
        if not server_rsa_keys:
            spub, spriv = rsa_generate_keys(1024)
            server_rsa_keys['pub'] = spub
            server_rsa_keys['priv'] = spriv
            
        # 4. 服务端生成对 Y_B 的保护签名
        server_hash = md5_hash(server_dh_pub)
        server_sig = rsa_sign(server_hash, server_rsa_keys['priv'])
        
        # 5. (可选) 服务端计算最终的共享密钥
        shared_secret = dh_compute_shared_secret(client_dh_pub, server_dh_priv, p)
        print(f"[*] Server computed shared secret: {shared_secret[:16]}...")
        
        return jsonify({
            'status': 'success',
            'server_dh_pub': server_dh_pub,
            'server_rsa_pub': server_rsa_keys['pub'],
            'signature': server_sig,
            'p': p,
            'g': g
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== 散列函数 ====================
@app.route('/api/hash/sha1', methods=['POST'])
def api_hash_sha1():
    data = request.json
    message = data.get('message', '')

    if not crypto_available:
        return jsonify({'error': 'Crypto library not loaded'}), 500

    try:
        hash_value = sha1_hash(message)
        return jsonify({'hash': hash_value})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hash/md5', methods=['POST'])
def api_hash_md5():
    data = request.json
    message = data.get('message', '')

    if not crypto_available:
        return jsonify({'error': 'Crypto library not loaded'}), 500

    try:
        hash_value = md5_hash(message)
        return jsonify({'hash': hash_value})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

import xml.etree.ElementTree as ET

# ==================== XML Configurations ====================
@app.route('/api/config/load', methods=['GET'])
def api_config_load():
    config_type = request.args.get('type')
    if not config_type:
        return jsonify({'error': 'type parameter is required'}), 400
    
    file_path = os.path.join(app.root_path, 'config', f'{config_type}_config.xml')
    if not os.path.exists(file_path):
        return jsonify({'error': f'Config file for {config_type} not found'}), 404
        
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        params = {}
        param_node = root.find('parameters')
        if param_node is not None:
            for child in param_node:
                params[child.tag] = child.text
        elif config_type == 'rsa':
            kg = root.find('key_generation')
            if kg is not None:
                for child in kg:
                    params[child.tag] = child.text
        return jsonify({'config': params})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== DH & RSA Sign Server ====================
server_rsa_pub = ""
server_rsa_priv = ""
if crypto_available:
    server_rsa_pub, server_rsa_priv = rsa_generate_keys(16)

@app.route('/api/dh/exchange', methods=['POST'])
def api_dh_exchange():
    data = request.json
    client_pub_dh = data.get('client_pub_dh')

    if not client_pub_dh or not crypto_available:
        return jsonify({'error': 'Missing client pg or crypto available'}), 400

    try:
        p, g = dh_generate_params()
        dh_pub, dh_priv = dh_generate_keypair(p, g)
        
        shared_secret = dh_compute_shared_secret(client_pub_dh, dh_priv, p)
        
        # Sign the hash of the shared secret
        server_sig = rsa_sign(shared_secret, server_rsa_priv)
        
        return jsonify({
            'server_pub_dh': dh_pub,
            'p': p,
            'g': g,
            'signature': server_sig,
            'server_rsa_pub': server_rsa_pub,
            'message': 'DH Exchange Successful'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== 辅助函数 ====================
@app.route('/api/status', methods=['GET'])
def api_status():
    return jsonify({'crypto_available': crypto_available})

# ==================== MiniMax AI Assistant ====================
import requests

@app.route('/api/assistant', methods=['POST'])
def api_assistant():
    data = request.json
    # 从本地获取配置的 API Key
    api_key = "sk-cp-6HxG_aJO6AUJy_LRSSgwIK_ms52VP8GNLpYUQAcE-mv55a8DrCXgeJ080cdir-Vx5XnpoNQQ9yQS7ib6w7FwNMC8CT3kfg-_AfSFNlz0RsmBR6TUbQ3DJ0Q"
    messages = data.get('messages', [])
    
    if not api_key or api_key == "改为你的MiniMaxAPI_KEY":
        return jsonify({'error': '请在 app.py 中本地配置好你的 API key。'}), 400
        
    url = "https://api.minimaxi.com/anthropic/v1/messages"

    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
    }
    
    # 将前端格式转换为 anthropic 支持的格式（去除多余字段如 name）
    anthropic_messages = []
    for msg in messages:
        anthropic_messages.append({
            "role": "user" if msg["role"] == "user" else "assistant",
            "content": msg["content"]
        })

    payload = {
        "model": "MiniMax-M2.7",
        "system": "你是密码学课程助手。回答时保持简洁清晰；涉及数学公式、加密推导、模运算、矩阵、概率、复杂度等内容时，统一使用 LaTeX 书写。行内公式用 $...$，独立公式用 $$...$$。",
        "messages": anthropic_messages,
        "max_tokens": 4096
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        resp_json = response.json()

        # Extract reply
        if 'content' in resp_json:
            reply = ""
            for block in resp_json['content']:
                if block.get('type') == 'text':
                    reply += block.get('text', '')
            return jsonify({'reply': reply})
        elif 'error' in resp_json:
            return jsonify({'error': resp_json['error'].get('message', 'MiniMax API Error')}), 500
        else:
            return jsonify({'error': 'Invalid response from MiniMax API', 'details': resp_json}), 500
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("=" * 50)
    print("密码学综合服务系统")
    print("=" * 50)
    print(f"C++ 加密库: {'已加载' if crypto_available else '未加载'}")
    print("启动服务: http://localhost:5000")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=True)
