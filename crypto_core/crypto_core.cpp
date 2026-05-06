#define CRYPTO_CORE_EXPORTS
#include "crypto_core.h"
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <ctime>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/des.h>
#include <openssl/rand.h>

// ==================== 工具函数 ====================
static std::string intToString(int val) {
    char buf[32];
    sprintf(buf, "%d", val);
    return buf;
}

static int modInverse(int a, int m) {
    a = a % m;
    for (int x = 1; x < m; x++) {
        if ((a * x) % m == 1) return x;
    }
    return 1;
}

// ==================== 仿射加密 ====================
// ==================== 128-bit big integer arithmetic ====================
class UInt128 {
public:
    unsigned int limb[4];

    UInt128() { memset(limb, 0, sizeof(limb)); }

    static UInt128 fromString(const char* text) {
        UInt128 value;
        if (!text) return value;
        while (*text && isspace((unsigned char)*text)) ++text;

        bool hex = text[0] == '0' && (text[1] == 'x' || text[1] == 'X');
        if (hex) {
            text += 2;
            while (*text) {
                int digit = 0;
                if (*text >= '0' && *text <= '9') digit = *text - '0';
                else if (*text >= 'a' && *text <= 'f') digit = *text - 'a' + 10;
                else if (*text >= 'A' && *text <= 'F') digit = *text - 'A' + 10;
                else { ++text; continue; }
                value.mulSmall(16);
                value.addSmall((unsigned int)digit);
                ++text;
            }
        } else {
            while (*text) {
                if (*text >= '0' && *text <= '9') {
                    value.mulSmall(10);
                    value.addSmall((unsigned int)(*text - '0'));
                }
                ++text;
            }
        }
        return value;
    }

    void addSmall(unsigned int x) {
        unsigned long long carry = x;
        for (int i = 0; i < 4 && carry; ++i) {
            unsigned long long sum = (unsigned long long)limb[i] + carry;
            limb[i] = (unsigned int)sum;
            carry = sum >> 32;
        }
    }

    void mulSmall(unsigned int x) {
        unsigned long long carry = 0;
        for (int i = 0; i < 4; ++i) {
            unsigned long long product = (unsigned long long)limb[i] * x + carry;
            limb[i] = (unsigned int)product;
            carry = product >> 32;
        }
    }

    int compare(const UInt128& other) const {
        for (int i = 3; i >= 0; --i) {
            if (limb[i] < other.limb[i]) return -1;
            if (limb[i] > other.limb[i]) return 1;
        }
        return 0;
    }
};

static bool isZero256(const unsigned int v[8]) {
    for (int i = 0; i < 8; ++i) if (v[i]) return false;
    return true;
}

static unsigned int divSmall256(unsigned int v[8], unsigned int divisor) {
    unsigned long long rem = 0;
    for (int i = 7; i >= 0; --i) {
        unsigned long long cur = (rem << 32) | v[i];
        v[i] = (unsigned int)(cur / divisor);
        rem = cur % divisor;
    }
    return (unsigned int)rem;
}

static std::string toDecimal256(const unsigned int input[8]) {
    unsigned int temp[8];
    memcpy(temp, input, sizeof(temp));
    if (isZero256(temp)) return "0";

    std::string digits;
    while (!isZero256(temp)) {
        digits.push_back((char)('0' + divSmall256(temp, 10)));
    }
    std::reverse(digits.begin(), digits.end());
    return digits;
}

CRYPTO_API void bigint128_add(const char* left, const char* right, char* output) {
    UInt128 a = UInt128::fromString(left);
    UInt128 b = UInt128::fromString(right);
    unsigned int result[8] = {0};
    unsigned long long carry = 0;
    for (int i = 0; i < 4; ++i) {
        unsigned long long sum = (unsigned long long)a.limb[i] + b.limb[i] + carry;
        result[i] = (unsigned int)sum;
        carry = sum >> 32;
    }
    result[4] = (unsigned int)carry;
    strcpy(output, toDecimal256(result).c_str());
}

CRYPTO_API void bigint128_sub(const char* left, const char* right, char* output) {
    UInt128 a = UInt128::fromString(left);
    UInt128 b = UInt128::fromString(right);
    bool negative = a.compare(b) < 0;
    const UInt128& hi = negative ? b : a;
    const UInt128& lo = negative ? a : b;
    unsigned int result[8] = {0};
    long long borrow = 0;
    for (int i = 0; i < 4; ++i) {
        long long diff = (long long)hi.limb[i] - lo.limb[i] - borrow;
        if (diff < 0) {
            diff += (1LL << 32);
            borrow = 1;
        } else {
            borrow = 0;
        }
        result[i] = (unsigned int)diff;
    }
    std::string text = toDecimal256(result);
    if (negative && text != "0") text.insert(text.begin(), '-');
    strcpy(output, text.c_str());
}

CRYPTO_API void bigint128_mul(const char* left, const char* right, char* output) {
    UInt128 a = UInt128::fromString(left);
    UInt128 b = UInt128::fromString(right);
    unsigned int result[8] = {0};

    for (int i = 0; i < 4; ++i) {
        unsigned long long carry = 0;
        for (int j = 0; j < 4; ++j) {
            unsigned long long cur = (unsigned long long)a.limb[i] * b.limb[j] + result[i + j] + carry;
            result[i + j] = (unsigned int)cur;
            carry = cur >> 32;
        }
        int k = i + 4;
        while (carry && k < 8) {
            unsigned long long cur = (unsigned long long)result[k] + carry;
            result[k] = (unsigned int)cur;
            carry = cur >> 32;
            ++k;
        }
    }

    strcpy(output, toDecimal256(result).c_str());
}

CRYPTO_API void affine_encrypt(const char* plaintext, const char* key_a, const char* key_b, char* output) {
    int a = atoi(key_a);
    int b = atoi(key_b);
    int len = strlen(plaintext);

    for (int i = 0; i < len; i++) {
        if (plaintext[i] >= 'a' && plaintext[i] <= 'z') {
            output[i] = ((a * (plaintext[i] - 'a') + b) % 26) + 'a';
        } else if (plaintext[i] >= 'A' && plaintext[i] <= 'Z') {
            output[i] = ((a * (plaintext[i] - 'A') + b) % 26) + 'A';
        } else {
            output[i] = plaintext[i];
        }
    }
    output[len] = '\0';
}

CRYPTO_API void affine_decrypt(const char* ciphertext, const char* key_a, const char* key_b, char* output) {
    int a = atoi(key_a);
    int b = atoi(key_b);
    int a_inv = modInverse(a, 26);
    int len = strlen(ciphertext);

    for (int i = 0; i < len; i++) {
        if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z') {
            output[i] = ((a_inv * ((ciphertext[i] - 'a' - b + 26) % 26)) % 26) + 'a';
        } else if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') {
            output[i] = ((a_inv * ((ciphertext[i] - 'A' - b + 26) % 26)) % 26) + 'A';
        } else {
            output[i] = ciphertext[i];
        }
    }
    output[len] = '\0';
}

// ==================== RC4 流密码 ====================
static unsigned char S[256];
static int rc4_initialized = 0;

CRYPTO_API void rc4_init(const char* key, int key_len) {
    rc4_initialized = 1;
    for (int i = 0; i < 256; i++) S[i] = i;

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) % 256;
        std::swap(S[i], S[j]);
    }
}

CRYPTO_API void rc4_encrypt(const char* input, int len, char* output) {
    if (!rc4_initialized) return;
    int i = 0, j = 0;
    for (int k = 0; k < len; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);
        int t = (S[i] + S[j]) % 256;
        output[k] = input[k] ^ S[t];
    }
    output[len] = '\0';
}

CRYPTO_API void rc4_decrypt(const char* input, int len, char* output) {
    rc4_encrypt(input, len, output);
}

// ==================== LFSR + J-K触发器 ====================
static unsigned char lfsr_register[16];
static unsigned char jk_state[2];
static int lfsr_initialized = 0;

CRYPTO_API void lfsr_jk_init(const char* seed, int seed_len) {
    lfsr_initialized = 1;
    memset(lfsr_register, 0, sizeof(lfsr_register));
    memset(jk_state, 0, sizeof(jk_state));

    for (int i = 0; i < seed_len && i < 16; i++) {
        lfsr_register[i] = seed[i];
    }

    // 初始化J-K触发器状态
    jk_state[0] = seed[seed_len % seed_len];
    jk_state[1] = seed[(seed_len + 1) % seed_len];
}

static unsigned char lfsr_generate() {
    unsigned char feedback = lfsr_register[15] ^ lfsr_register[14] ^ lfsr_register[13] ^ lfsr_register[11];

    for (int i = 15; i > 0; i--) {
        lfsr_register[i] = lfsr_register[i - 1];
    }
    lfsr_register[0] = feedback;

    // J-K触发器
    unsigned char j = jk_state[0];
    unsigned char k = jk_state[1];
    unsigned char clk = lfsr_register[0];

    if (clk) {
        jk_state[1] = j & jk_state[0];
        jk_state[0] = k ^ jk_state[0];
    }

    return lfsr_register[15] ^ jk_state[0];
}

CRYPTO_API void lfsr_jk_encrypt(const char* input, int len, char* output) {
    if (!lfsr_initialized) return;
    for (int i = 0; i < len; i++) {
        output[i] = input[i] ^ lfsr_generate();
    }
    output[len] = '\0';
}

CRYPTO_API void lfsr_jk_decrypt(const char* input, int len, char* output) {
    lfsr_jk_encrypt(input, len, output);
}

// ==================== DES 对称加密 ====================
CRYPTO_API void des_encrypt(const char* plaintext, const char* key, char* output) {
    DES_key_schedule schedule;
    DES_cblock key_block;

    // 处理密钥（取前8字节或填充）
    int key_len = strlen(key);
    for (int i = 0; i < 8; i++) {
        key_block[i] = key[i % key_len];
    }

    DES_set_key_unchecked(&key_block, &schedule);

    int len = strlen(plaintext);
    int padded_len = ((len / 8) + 1) * 8;
    int pad_val = padded_len - len;
    unsigned char* buffer = new unsigned char[padded_len];
    memcpy(buffer, plaintext, len);
    for (int i = len; i < padded_len; i++) {
        buffer[i] = pad_val;
    }

    for (int i = 0; i < padded_len; i += 8) {
        DES_ecb_encrypt((DES_cblock*)(buffer + i), (DES_cblock*)(output + i), &schedule, DES_ENCRYPT);
    }
    
    // 转为十六进制输出，防止由于密文中存在 \x00 导致后面当字符串处理时被截断报错
    int hex_offset = 0;
    char* temp_hex = new char[padded_len * 2 + 1];
    for (int i = 0; i < padded_len; i++) {
        hex_offset += sprintf(temp_hex + hex_offset, "%02x", (unsigned char)output[i]);
    }
    strcpy(output, temp_hex);
    
    delete[] temp_hex;
    delete[] buffer;
}

CRYPTO_API void des_decrypt(const char* ciphertext_hex, const char* key, char* output) {
    DES_key_schedule schedule;
    DES_cblock key_block;

    int key_len = strlen(key);
    for (int i = 0; i < 8; i++) {
        key_block[i] = key[i % key_len];
    }

    DES_set_key_unchecked(&key_block, &schedule);

    int hex_len = strlen(ciphertext_hex);
    int len = hex_len / 2;
    unsigned char* buffer = new unsigned char[len];
    for (int i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(ciphertext_hex + i * 2, "%02x", &byte);
        buffer[i] = byte;
    }

    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock*)(buffer + i), (DES_cblock*)(output + i), &schedule, DES_DECRYPT);
    }

    // 去除填充
    int padding = output[len - 1];
    output[len - padding] = '\0';

    delete[] buffer;
}

// ==================== RSA 非对称加密 ====================
static long long mod_exp(long long base, long long exp, long long mod) {
    long long res = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) res = (res * base) % mod;
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return res;
}

static long long extgcd(long long a, long long b, long long &x, long long &y) {
    if (b == 0) { x = 1; y = 0; return a; }
    long long x1, y1;
    long long d = extgcd(b, a % b, x1, y1);
    x = y1;
    y = x1 - y1 * (a / b);
    return d;
}

static bool is_prime(long long n) {
    if(n < 2) return false;
    for(long long i=2; i*i<=n; ++i) {
        if(n%i == 0) return false;
    }
    return true;
}

static long long get_rand_prime() {
    while(true) {
        // 修改随机区间：生成 100 到 249 的素数，确保 n = p*q 大于 255 避免丢失单字节，同时小于 65535 不超 `%04llx` 格式的限制
        unsigned int r = 0;
        if (RAND_bytes((unsigned char*)&r, sizeof(r)) != 1) {
            r = (unsigned int)rand();
        }
        long long p = r % 150 + 100;
        if (is_prime(p)) return p;
    }
}

CRYPTO_API void rsa_generate_keys(int bits, char* public_key, char* private_key) {
    static bool seeded = false;
    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = true;
    }

    long long p, q;
    do { p = get_rand_prime(); q = get_rand_prime(); } while(p == q);
    long long n = p * q;
    long long phi = (p-1)*(q-1);
    long long e = 3;
    while(true) {
        long long x, y;
        if (extgcd(e, phi, x, y) == 1) break;
        e += 2;
    }
    long long x, y;
    extgcd(e, phi, x, y);
    long long d = (x % phi + phi) % phi;
    sprintf(public_key, "%lld,%lld", n, e);
    sprintf(private_key, "%lld,%lld", n, d);
}

CRYPTO_API void rsa_encrypt(const char* plaintext, const char* public_key, char* output) {
    long long n, e;
    sscanf(public_key, "%lld,%lld", &n, &e);
    int len = strlen(plaintext);
    int offset = 0;
    for (int i=0; i<len; i++) {
        long long m = (unsigned char)plaintext[i];
        long long c = mod_exp(m, e, n);
        offset += sprintf(output + offset, "%04llx", c);
    }
    output[offset] = '\0';
}

CRYPTO_API void rsa_decrypt(const char* ciphertext_hex, const char* private_key, char* output) {
    long long n, d;
    sscanf(private_key, "%lld,%lld", &n, &d);
    int len = strlen(ciphertext_hex) / 4;
    for (int i=0; i<len; i++) {
        long long c;
        sscanf(ciphertext_hex + i*4, "%04llx", &c);
        long long m = mod_exp(c, d, n);
        output[i] = (char)m;
    }
    output[len] = '\0';
}

// ==================== RSA 数字签名 ====================
CRYPTO_API void rsa_sign(const char* message, const char* private_key, char* signature) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message, strlen(message), hash);
    long long n, d;
    sscanf(private_key, "%lld,%lld", &n, &d);
    int offset = 0;
    for (int i=0; i<SHA256_DIGEST_LENGTH; i++) {
        long long m = hash[i];
        long long c = mod_exp(m, d, n);
        offset += sprintf(signature + offset, "%04llx", c);
    }
    signature[offset] = '\0';
}

CRYPTO_API int rsa_verify(const char* message, const char* signature_hex, const char* public_key) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message, strlen(message), hash);
    long long n, e;
    sscanf(public_key, "%lld,%lld", &n, &e);
    int len = strlen(signature_hex) / 4;
    if (len != SHA256_DIGEST_LENGTH) return 0;
    for (int i=0; i<len; i++) {
        long long c;
        sscanf(signature_hex + i*4, "%04llx", &c);
        long long m = mod_exp(c, e, n);
        if ((unsigned char)m != hash[i]) return 0;
    }
    return 1;
}

// ==================== D-H 密钥交换 ====================
CRYPTO_API void dh_generate_params(char* p, char* g) {
    // 使用预定义的素数和原根（注意：BN_hex2bn不能带有 0x 前缀）
    strcpy(p, "D5F6C9C2A7B9E8F1D3A4B6C8E9F2A1B4C6D8E0F3A5B7C9D1E4F6A8B0C2D5E7F9A1B3C5D7E9F0A2B4C6D8E1F3A5B7C0D2E4F6A8B1C3D5E7F9A2B4C6D9E0F2A4B6C8D0E3A5B7C1D3E5F7A9B2C4D6E8F1A3B5C7D0E2A4B6C8D1E3A5B7C9D2E4F6A8B0C2D4E6F8A1B3C5D7E9F1A3B5C7D0E2A4B6C8D1E3A5B7C0D2E4F6A8B1C3D5E7F9A2B4C6D8E0F3A5B7C1D3E5F7A9B2C4D6E8F0A2B4C6D9E1F3A5B7C0D2E4F6A8B1C3D5E7F9A2B4C6D8E0F2A4B6C8D1E3A5B7C9D2E4F6A8B0C2D4E6F8A1B3C5D7E9F1");
    strcpy(g, "5");
}

CRYPTO_API void dh_generate_keypair(const char* p, const char* g, char* public_key, char* private_key) {
    BIGNUM* p_bn = BN_new();
    BIGNUM* g_bn = BN_new();
    BN_hex2bn(&p_bn, p);
    BN_hex2bn(&g_bn, g);

    BIGNUM* priv = BN_new();
    BIGNUM* pub = BN_new();
    BN_CTX* ctx = BN_CTX_new();

    BN_rand(priv, 256, -1, 0);
    BN_mod_exp(pub, g_bn, priv, p_bn, ctx);

    char* priv_hex = BN_bn2hex(priv);
    char* pub_hex = BN_bn2hex(pub);

    strcpy(private_key, priv_hex);
    strcpy(public_key, pub_hex);

    OPENSSL_free(priv_hex);
    OPENSSL_free(pub_hex);
    BN_CTX_free(ctx);
    BN_free(p_bn);
    BN_free(g_bn);
    BN_free(priv);
    BN_free(pub);
}

CRYPTO_API void dh_compute_shared_secret(const char* public_key, const char* private_key, const char* p, char* shared_secret) {
    BIGNUM* p_bn = BN_new();
    BIGNUM* pub_bn = BN_new();
    BIGNUM* priv_bn = BN_new();

    BN_hex2bn(&p_bn, p);
    BN_hex2bn(&pub_bn, public_key);
    BN_hex2bn(&priv_bn, private_key);

    BIGNUM* secret = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BN_mod_exp(secret, pub_bn, priv_bn, p_bn, ctx);

    char* secret_hex = BN_bn2hex(secret);
    strcpy(shared_secret, secret_hex);

    OPENSSL_free(secret_hex);
    BN_CTX_free(ctx);
    BN_free(p_bn);
    BN_free(pub_bn);
    BN_free(priv_bn);
    BN_free(secret);
}

// ==================== 散列函数 ====================
CRYPTO_API void sha1_hash(const char* input, int len, char* output) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)input, len, hash);

    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(output + i * 2, "%02x", hash[i]);
    }
    output[SHA_DIGEST_LENGTH * 2] = '\0';
}

CRYPTO_API void md5_hash(const char* input, int len, char* output) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)input, len, hash);

    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(output + i * 2, "%02x", hash[i]);
    }
    output[MD5_DIGEST_LENGTH * 2] = '\0';
}

// ==================== 清理资源 ====================
CRYPTO_API void cleanup() {
    rc4_initialized = 0;
    lfsr_initialized = 0;
}
