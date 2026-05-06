"""
密码学核心算法包装器
使用 ctypes 调用 C++ DLL
"""
import ctypes
import os
from pathlib import Path

# Keep references alive for add_dll_directory handles on Windows.
_DLL_DIR_HANDLES = []

def _candidate_runtime_dirs(base_dir: Path):
    dirs = [
        base_dir,
        base_dir / "bin",
        base_dir / "dlls",
    ]

    env_vars = ["OPENSSL_ROOT_DIR", "OPENSSL_DIR", "MINGW_HOME", "MSYS2_ROOT"]
    for key in env_vars:
        value = os.environ.get(key)
        if not value:
            continue
        p = Path(value)
        dirs.extend([p, p / "bin", p / "mingw64" / "bin"])

    dirs.extend([
        Path(r"C:\Program Files\OpenSSL-Win64\bin"),
        Path(r"C:\Program Files\Git\mingw64\bin"),
        Path(r"C:\Program Files (x86)\Dev-Cpp\MinGW64\bin"),
    ])

    unique_dirs = []
    seen = set()
    for d in dirs:
        key = str(d).lower()
        if key in seen or not d.exists():
            continue
        seen.add(key)
        unique_dirs.append(d)
    return unique_dirs

def _prepare_windows_runtime_dirs(base_dir: Path):
    if os.name != "nt":
        return

    runtime_dirs = _candidate_runtime_dirs(base_dir)
    for d in runtime_dirs:
        # Python 3.8+ supports explicit DLL search directories on Windows.
        if hasattr(os, "add_dll_directory"):
            _DLL_DIR_HANDLES.append(os.add_dll_directory(str(d)))

    # Fallback for subprocesses or older loading behaviors.
    current_path = os.environ.get("PATH", "")
    prefix = os.pathsep.join(str(d) for d in runtime_dirs)
    if prefix:
        os.environ["PATH"] = prefix + os.pathsep + current_path

# 加载 DLL
def load_dll():
    base_dir = Path(__file__).parent
    _prepare_windows_runtime_dirs(base_dir)
    dll_path = base_dir / "crypto_core.dll"
    if not dll_path.exists():
        raise FileNotFoundError(f"DLL not found: {dll_path}")
    return ctypes.CDLL(str(dll_path))

try:
    lib = load_dll()
except (FileNotFoundError, OSError):
    lib = None

# ==================== 仿射加密 ====================
def affine_encrypt(plaintext: str, key_a: int, key_b: int) -> str:
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    output = ctypes.create_string_buffer(1024)
    lib.affine_encrypt(plaintext.encode(), str(key_a).encode(), str(key_b).encode(), output)
    return output.value.decode()

def affine_decrypt(ciphertext: str, key_a: int, key_b: int) -> str:
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    output = ctypes.create_string_buffer(1024)
    lib.affine_decrypt(ciphertext.encode(), str(key_a).encode(), str(key_b).encode(), output)
    return output.value.decode()

# ==================== RC4 流密码 ====================
def bigint128_add(left: str, right: str) -> str:
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    output = ctypes.create_string_buffer(128)
    lib.bigint128_add(str(left).encode(), str(right).encode(), output)
    return output.value.decode()

def bigint128_sub(left: str, right: str) -> str:
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    output = ctypes.create_string_buffer(128)
    lib.bigint128_sub(str(left).encode(), str(right).encode(), output)
    return output.value.decode()

def bigint128_mul(left: str, right: str) -> str:
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    output = ctypes.create_string_buffer(128)
    lib.bigint128_mul(str(left).encode(), str(right).encode(), output)
    return output.value.decode()

def rc4_init(key: bytes):
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    lib.rc4_init(key, len(key))

def rc4_encrypt(plaintext: bytes) -> bytes:
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    output = ctypes.create_string_buffer(len(plaintext) + 1)
    lib.rc4_encrypt(plaintext, len(plaintext), output)
    return output.value

def rc4_decrypt(ciphertext: bytes) -> bytes:
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    output = ctypes.create_string_buffer(len(ciphertext) + 1)
    lib.rc4_decrypt(ciphertext, len(ciphertext), output)
    return output.value

# ==================== LFSR + J-K触发器 ====================
def lfsr_jk_init(seed: bytes):
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    lib.lfsr_jk_init(seed, len(seed))

def lfsr_jk_encrypt(plaintext: bytes) -> bytes:
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    output = ctypes.create_string_buffer(len(plaintext) + 1)
    lib.lfsr_jk_encrypt(plaintext, len(plaintext), output)
    return output.value

def lfsr_jk_decrypt(ciphertext: bytes) -> bytes:
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    output = ctypes.create_string_buffer(len(ciphertext) + 1)
    lib.lfsr_jk_decrypt(ciphertext, len(ciphertext), output)
    return output.value

# ==================== DES 对称加密 ====================
def des_encrypt(plaintext: str, key: str) -> str:
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    output = ctypes.create_string_buffer(4096)
    lib.des_encrypt(plaintext.encode(), key.encode(), output)
    return output.value.decode()

def des_decrypt(ciphertext_hex: str, key: str) -> str:
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    output = ctypes.create_string_buffer(4096)
    lib.des_decrypt(ciphertext_hex.encode(), key.encode(), output)
    return output.value.decode()

# ==================== RSA 非对称加密 ====================
def rsa_generate_keys(bits: int = 1024):
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    public_key = ctypes.create_string_buffer(4096)
    private_key = ctypes.create_string_buffer(4096)
    lib.rsa_generate_keys(bits, public_key, private_key)
    return public_key.value.decode(), private_key.value.decode()

def rsa_encrypt(plaintext: str, public_key: str) -> str:
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    output = ctypes.create_string_buffer(4096)
    lib.rsa_encrypt(plaintext.encode(), public_key.encode(), output)
    return output.value.decode()

def rsa_decrypt(ciphertext_hex: str, private_key: str) -> str:
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    output = ctypes.create_string_buffer(4096)
    lib.rsa_decrypt(ciphertext_hex.encode(), private_key.encode(), output)
    return output.value.decode()

# ==================== RSA 数字签名 ====================
def rsa_sign(message: str, private_key: str) -> str:
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    output = ctypes.create_string_buffer(4096)
    lib.rsa_sign(message.encode(), private_key.encode(), output)
    return output.value.decode()

def rsa_verify(message: str, signature: str, public_key: str) -> bool:
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    return bool(lib.rsa_verify(message.encode(), signature.encode(), public_key.encode()))

# ==================== D-H 密钥交换 ====================
def dh_generate_params():
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    p = ctypes.create_string_buffer(512)
    g = ctypes.create_string_buffer(64)
    lib.dh_generate_params(p, g)
    return p.value.decode(), g.value.decode()

def dh_generate_keypair(p: str, g: str):
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    public_key = ctypes.create_string_buffer(512)
    private_key = ctypes.create_string_buffer(512)
    lib.dh_generate_keypair(p.encode(), g.encode(), public_key, private_key)
    return public_key.value.decode(), private_key.value.decode()

def dh_compute_shared_secret(public_key: str, private_key: str, p: str) -> str:
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    shared_secret = ctypes.create_string_buffer(512)
    lib.dh_compute_shared_secret(public_key.encode(), private_key.encode(), p.encode(), shared_secret)
    return shared_secret.value.decode()

# ==================== 散列函数 ====================
def sha1_hash(data: str) -> str:
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    output = ctypes.create_string_buffer(64)
    lib.sha1_hash(data.encode(), len(data), output)
    return output.value.decode()

def md5_hash(data: str) -> str:
    if lib is None:
        raise RuntimeError("Crypto DLL not loaded")
    output = ctypes.create_string_buffer(64)
    lib.md5_hash(data.encode(), len(data), output)
    return output.value.decode()

def cleanup():
    if lib is None:
        return
    lib.cleanup()
