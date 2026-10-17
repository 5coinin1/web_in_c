#ifndef STUB_OPENSSL_CRYPTO_H
#define STUB_OPENSSL_CRYPTO_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
void OPENSSL_cleanse(void *ptr, size_t len);
int CRYPTO_memcmp(const void *a, const void *b, size_t len);
#ifdef __cplusplus
}
#endif
#endif
