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

static int gcd_int(int a, int b) {
    a = abs(a);
    b = abs(b);
    while (b != 0) {
        int t = a % b;
        a = b;
        b = t;
    }
    return a;
}

static int positive_mod(int a, int m) {
    int r = a % m;
    return r < 0 ? r + m : r;
}

static int modInverse(int a, int m) {
    if (m <= 1) return 0;

    int original_m = m;
    a = positive_mod(a, m);

    int old_r = a, r = m;
    int old_s = 1, s = 0;
    while (r != 0) {
        int q = old_r / r;
        int next_r = old_r - q * r;
        old_r = r;
        r = next_r;

        int next_s = old_s - q * s;
        old_s = s;
        s = next_s;
    }

    if (old_r != 1) return 0;
    return positive_mod(old_s, original_m);
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
    if (gcd_int(a, 26) != 1) {
        output[0] = '\0';
        return;
    }

    for (int i = 0; i < len; i++) {
        if (plaintext[i] >= 'a' && plaintext[i] <= 'z') {
            output[i] = positive_mod(a * (plaintext[i] - 'a') + b, 26) + 'a';
        } else if (plaintext[i] >= 'A' && plaintext[i] <= 'Z') {
            output[i] = positive_mod(a * (plaintext[i] - 'A') + b, 26) + 'A';
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
    if (a_inv == 0) {
        output[0] = '\0';
        return;
    }

    for (int i = 0; i < len; i++) {
        if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z') {
            output[i] = positive_mod(a_inv * positive_mod(ciphertext[i] - 'a' - b, 26), 26) + 'a';
        } else if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') {
            output[i] = positive_mod(a_inv * positive_mod(ciphertext[i] - 'A' - b, 26), 26) + 'A';
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
    if (!key || key_len <= 0) {
        rc4_initialized = 0;
        return;
    }

    rc4_initialized = 1;
    for (int i = 0; i < 256; i++) S[i] = i;

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) % 256;
        std::swap(S[i], S[j]);
    }
}

CRYPTO_API void rc4_encrypt(const char* input, int len, char* output) {
    if (!rc4_initialized) {
        output[0] = '\0';
        return;
    }
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

// ==================== LFSR + J-K 触发器 ====================
static unsigned char lfsr_register[16];
static unsigned char jk_q = 0;
static int lfsr_initialized = 0;

CRYPTO_API void lfsr_jk_init(const char* seed, int seed_len) {
    if (!seed || seed_len <= 0) {
        lfsr_initialized = 0;
        return;
    }

    lfsr_initialized = 1;
    memset(lfsr_register, 0, sizeof(lfsr_register));

    for (int i = 0; i < 16; i++) {
        int byte_index = i / 8;
        int bit_index = 7 - (i % 8);
        if (byte_index < seed_len) {
            lfsr_register[i] = ((unsigned char)seed[byte_index] >> bit_index) & 1;
        }
    }

    // 初始化 LFSR 状态，避免全 0 状态锁死
    bool all_zero = true;
    for (int i = 0; i < 16; i++) {
        if (lfsr_register[i]) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) lfsr_register[15] = 1;

    jk_q = ((unsigned char)seed[0]) & 1;
}

static unsigned char jk_next(unsigned char j, unsigned char k, unsigned char q) {
    j &= 1;
    k &= 1;
    q &= 1;

    if (j == 0 && k == 0) return q;       // hold
    if (j == 0 && k == 1) return 0;       // reset
    if (j == 1 && k == 0) return 1;       // set
    return q ^ 1;                         // toggle
}

static unsigned char lfsr_generate_bit() {
    unsigned char output_bit = lfsr_register[15] & 1;
    unsigned char feedback = (lfsr_register[15] ^ lfsr_register[14] ^ lfsr_register[13] ^ lfsr_register[11]) & 1;

    for (int i = 15; i > 0; i--) {
        lfsr_register[i] = lfsr_register[i - 1];
    }
    lfsr_register[0] = feedback;

    // J-K 触发器
    unsigned char j = lfsr_register[1];
    unsigned char k = lfsr_register[3];
    jk_q = jk_next(j, k, jk_q);

    return output_bit ^ jk_q;
}

static unsigned char lfsr_generate_byte() {
    unsigned char byte = 0;
    for (int i = 0; i < 8; i++) {
        byte = (unsigned char)((byte << 1) | lfsr_generate_bit());
    }
    return byte;
}

CRYPTO_API void lfsr_jk_encrypt(const char* input, int len, char* output) {
    if (!lfsr_initialized) {
        output[0] = '\0';
        return;
    }
    for (int i = 0; i < len; i++) {
        output[i] = input[i] ^ lfsr_generate_byte();
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

    // 处理密钥，短密钥循环填充到 8 字节
    if (!key || key[0] == '\0') {
        output[0] = '\0';
        return;
    }
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
    
    // 转为十六进制输出，避免密文中的 \x00 截断 C 字符串
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

    if (!key || key[0] == '\0') {
        output[0] = '\0';
        return;
    }
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

    // 去除 PKCS#7 风格填充
    int padding = output[len - 1];
    output[len - padding] = '\0';

    delete[] buffer;
}

// ==================== RSA 非对称加密 ====================
static long long extgcd(long long a, long long b, long long &x, long long &y) {
    if (b == 0) { x = 1; y = 0; return a; }
    long long x1, y1;
    long long d = extgcd(b, a % b, x1, y1);
    x = y1;
    y = x1 - y1 * (a / b);
    return d;
}


static bool split_key(const char* key, std::string& n_text, std::string& exp_text) {
    if (!key) return false;
    const char* comma = strchr(key, ',');
    if (!comma || comma == key || comma[1] == '\0') return false;
    n_text.assign(key, comma - key);
    exp_text.assign(comma + 1);
    return true;
}

static BIGNUM* bn_from_hex_text(const std::string& text) {
    BIGNUM* bn = nullptr;
    if (BN_hex2bn(&bn, text.c_str()) == 0) {
        BN_free(bn);
        return nullptr;
    }
    return bn;
}

static int rsa_hex_width(const BIGNUM* n) {
    return BN_num_bytes(n) * 2;
}

static void write_padded_hex(char* output, int& offset, const BIGNUM* value, int width) {
    char* hex = BN_bn2hex(value);
    int len = (int)strlen(hex);
    for (int i = len; i < width; i++) output[offset++] = '0';
    memcpy(output + offset, hex, len);
    offset += len;
    OPENSSL_free(hex);
}

CRYPTO_API void rsa_generate_keys(int bits, char* public_key, char* private_key) {
    if (bits < 512) bits = 512;
    if (bits % 2 != 0) bits++;

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
    BIGNUM* n = BN_new();
    BIGNUM* phi = BN_new();
    BIGNUM* p_minus_1 = BN_new();
    BIGNUM* q_minus_1 = BN_new();
    BIGNUM* e = BN_new();
    BIGNUM* d = BN_new();
    BIGNUM* gcd = BN_new();

    BN_set_word(e, 65537);
    do {
        BN_generate_prime_ex(p, bits / 2, 0, nullptr, nullptr, nullptr);
        do {
            BN_generate_prime_ex(q, bits / 2, 0, nullptr, nullptr, nullptr);
        } while (BN_cmp(p, q) == 0);

        BN_sub(p_minus_1, p, BN_value_one());
        BN_sub(q_minus_1, q, BN_value_one());
        BN_mul(phi, p_minus_1, q_minus_1, ctx);
        BN_gcd(gcd, e, phi, ctx);
    } while (!BN_is_one(gcd));

    BN_mul(n, p, q, ctx);
    BN_mod_inverse(d, e, phi, ctx);

    char* n_hex = BN_bn2hex(n);
    char* e_hex = BN_bn2hex(e);
    char* d_hex = BN_bn2hex(d);
    sprintf(public_key, "%s,%s", n_hex, e_hex);
    sprintf(private_key, "%s,%s", n_hex, d_hex);

    OPENSSL_free(n_hex);
    OPENSSL_free(e_hex);
    OPENSSL_free(d_hex);
    BN_free(p);
    BN_free(q);
    BN_free(n);
    BN_free(phi);
    BN_free(p_minus_1);
    BN_free(q_minus_1);
    BN_free(e);
    BN_free(d);
    BN_free(gcd);
    BN_CTX_free(ctx);
}

CRYPTO_API void rsa_encrypt(const char* plaintext, const char* public_key, char* output) {
    std::string n_text, e_text;
    if (!split_key(public_key, n_text, e_text)) {
        output[0] = '\0';
        return;
    }

    BIGNUM* n = bn_from_hex_text(n_text);
    BIGNUM* e = bn_from_hex_text(e_text);
    if (!n || !e) {
        output[0] = '\0';
        BN_free(n);
        BN_free(e);
        return;
    }

    BIGNUM* m = BN_new();
    BIGNUM* c = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    int width = rsa_hex_width(n);
    int len = strlen(plaintext);
    int offset = 0;
    for (int i = 0; i < len; i++) {
        BN_set_word(m, (unsigned char)plaintext[i]);
        BN_mod_exp(c, m, e, n, ctx);
        write_padded_hex(output, offset, c, width);
    }
    output[offset] = '\0';

    BN_free(n);
    BN_free(e);
    BN_free(m);
    BN_free(c);
    BN_CTX_free(ctx);
}

CRYPTO_API void rsa_decrypt(const char* ciphertext_hex, const char* private_key, char* output) {
    std::string n_text, d_text;
    if (!split_key(private_key, n_text, d_text)) {
        output[0] = '\0';
        return;
    }

    BIGNUM* n = bn_from_hex_text(n_text);
    BIGNUM* d = bn_from_hex_text(d_text);
    if (!n || !d) {
        output[0] = '\0';
        BN_free(n);
        BN_free(d);
        return;
    }

    BIGNUM* c = BN_new();
    BIGNUM* m = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    int width = rsa_hex_width(n);
    int hex_len = strlen(ciphertext_hex);
    if (width <= 0 || hex_len % width != 0) {
        output[0] = '\0';
    } else {
        int blocks = hex_len / width;
        std::string chunk;
        for (int i = 0; i < blocks; i++) {
            chunk.assign(ciphertext_hex + i * width, width);
            BN_hex2bn(&c, chunk.c_str());
            BN_mod_exp(m, c, d, n, ctx);
            output[i] = (char)BN_get_word(m);
        }
        output[blocks] = '\0';
    }

    BN_free(n);
    BN_free(d);
    BN_free(c);
    BN_free(m);
    BN_CTX_free(ctx);
}

CRYPTO_API void rsa_sign(const char* message, const char* private_key, char* signature) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message, strlen(message), hash);

    std::string n_text, d_text;
    if (!split_key(private_key, n_text, d_text)) {
        signature[0] = '\0';
        return;
    }

    BIGNUM* n = bn_from_hex_text(n_text);
    BIGNUM* d = bn_from_hex_text(d_text);
    if (!n || !d) {
        signature[0] = '\0';
        BN_free(n);
        BN_free(d);
        return;
    }

    BIGNUM* m = BN_new();
    BIGNUM* s = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    int width = rsa_hex_width(n);
    int offset = 0;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        BN_set_word(m, hash[i]);
        BN_mod_exp(s, m, d, n, ctx);
        write_padded_hex(signature, offset, s, width);
    }
    signature[offset] = '\0';

    BN_free(n);
    BN_free(d);
    BN_free(m);
    BN_free(s);
    BN_CTX_free(ctx);
}

CRYPTO_API int rsa_verify(const char* message, const char* signature_hex, const char* public_key) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message, strlen(message), hash);

    std::string n_text, e_text;
    if (!split_key(public_key, n_text, e_text)) return 0;

    BIGNUM* n = bn_from_hex_text(n_text);
    BIGNUM* e = bn_from_hex_text(e_text);
    if (!n || !e) {
        BN_free(n);
        BN_free(e);
        return 0;
    }

    BIGNUM* s = BN_new();
    BIGNUM* m = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    int width = rsa_hex_width(n);
    int sig_len = strlen(signature_hex);
    if (width <= 0 || sig_len != SHA256_DIGEST_LENGTH * width) {
        BN_free(n);
        BN_free(e);
        BN_free(s);
        BN_free(m);
        BN_CTX_free(ctx);
        return 0;
    }

    std::string chunk;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        chunk.assign(signature_hex + i * width, width);
        BN_hex2bn(&s, chunk.c_str());
        BN_mod_exp(m, s, e, n, ctx);
        if ((unsigned char)BN_get_word(m) != hash[i]) {
            BN_free(n);
            BN_free(e);
            BN_free(s);
            BN_free(m);
            BN_CTX_free(ctx);
            return 0;
        }
    }

    BN_free(n);
    BN_free(e);
    BN_free(s);
    BN_free(m);
    BN_CTX_free(ctx);
    return 1;
}

CRYPTO_API void dh_generate_params(char* p, char* g) {
    // 使用 RFC 3526 2048-bit MODP 组参数，生成元为 2
    BIGNUM* p_bn = BN_get_rfc3526_prime_2048(nullptr);
    char* p_hex = BN_bn2hex(p_bn);
    strcpy(p, p_hex);
    strcpy(g, "2");
    OPENSSL_free(p_hex);
    BN_free(p_bn);
}

CRYPTO_API void dh_generate_keypair(const char* p, const char* g, char* public_key, char* private_key) {
    BIGNUM* p_bn = BN_new();
    BIGNUM* g_bn = BN_new();
    BN_hex2bn(&p_bn, p);
    BN_hex2bn(&g_bn, g);

    BIGNUM* priv = BN_new();
    BIGNUM* pub = BN_new();
    BN_CTX* ctx = BN_CTX_new();

    BIGNUM* range = BN_dup(p_bn);
    BN_sub_word(range, 3);
    BN_rand_range(priv, range);
    BN_add_word(priv, 2);
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
    BN_free(range);
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
