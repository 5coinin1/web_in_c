/* Minimal OpenSSL stub for the Chapter-4 fuzzing target.
 *
 * The fuzz harness only exercises auth_store_parse(), which performs no
 * cryptography. auth.c nevertheless #includes the OpenSSL headers and links
 * SHA256()/RAND_bytes()/CRYPTO_memcmp(), so without libssl-dev installed the
 * object would not build. These stubs provide just those symbols, letting the
 * parser be fuzzed anywhere (incl. WSL) without installing libssl-dev.
 *
 * They are NEVER executed by the fuzz harness (only auth_register/auth_init/
 * auth_check call them), so they do not affect fuzzing results. */
#ifndef STUB_OPENSSL_SHA_H
#define STUB_OPENSSL_SHA_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
#ifdef __cplusplus
}
#endif
#endif
