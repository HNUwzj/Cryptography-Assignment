#pragma once

#ifdef CRYPTO_CORE_EXPORTS
#define CRYPTO_API __declspec(dllexport)
#else
#define CRYPTO_API __declspec(dllimport)
#endif

extern "C" {
    // 仿射加密
    CRYPTO_API void affine_encrypt(const char* plaintext, const char* key_a, const char* key_b, char* output);
    CRYPTO_API void affine_decrypt(const char* ciphertext, const char* key_a, const char* key_b, char* output);

    // 128-bit big integer arithmetic
    CRYPTO_API void bigint128_add(const char* left, const char* right, char* output);
    CRYPTO_API void bigint128_sub(const char* left, const char* right, char* output);
    CRYPTO_API void bigint128_mul(const char* left, const char* right, char* output);

    // 流密码 - RC4
    CRYPTO_API void rc4_init(const char* key, int key_len);
    CRYPTO_API void rc4_encrypt(const char* input, int len, char* output);
    CRYPTO_API void rc4_decrypt(const char* input, int len, char* output);

    // 流密码 - LFSR+J-K触发器
    CRYPTO_API void lfsr_jk_init(const char* seed, int seed_len);
    CRYPTO_API void lfsr_jk_encrypt(const char* input, int len, char* output);
    CRYPTO_API void lfsr_jk_decrypt(const char* input, int len, char* output);

    // 对称加密 - DES
    CRYPTO_API void des_encrypt(const char* plaintext, const char* key, char* output);
    CRYPTO_API void des_decrypt(const char* ciphertext, const char* key, char* output);

    // 非对称加密 - RSA (使用Windows CryptoAPI)
    CRYPTO_API void rsa_generate_keys(int bits, char* public_key, char* private_key);
    CRYPTO_API void rsa_encrypt(const char* plaintext, const char* public_key, char* output);
    CRYPTO_API void rsa_decrypt(const char* ciphertext, const char* private_key, char* output);

    // 数字签名
    CRYPTO_API void rsa_sign(const char* message, const char* private_key, char* signature);
    CRYPTO_API int rsa_verify(const char* message, const char* signature, const char* public_key);

    // D-H 密钥交换
    CRYPTO_API void dh_generate_params(char* p, char* g);
    CRYPTO_API void dh_generate_keypair(const char* p, const char* g, char* public_key, char* private_key);
    CRYPTO_API void dh_compute_shared_secret(const char* public_key, const char* private_key, const char* p, char* shared_secret);

    // 散列函数
    CRYPTO_API void sha1_hash(const char* input, int len, char* output);
    CRYPTO_API void md5_hash(const char* input, int len, char* output);

    // 清理资源
    CRYPTO_API void cleanup();
}
