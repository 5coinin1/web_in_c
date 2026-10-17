/* Stub implementations of the tiny OpenSSL surface auth.c links against.
 * See stubs/openssl/*.h -- never executed by the fuzz harness. */
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <string.h>

unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md) {
    (void)d; (void)n;
    for (size_t i = 0; i < 32; i++) md[i] = 0;
    return md;
}

int RAND_bytes(unsigned char *buf, int num) {
    for (int i = 0; i < num; i++) buf[i] = (unsigned char)i;
    return 1;
}

void OPENSSL_cleanse(void *ptr, size_t len) {
    unsigned char *p = (unsigned char *)ptr;
    for (size_t i = 0; i < len; i++) p[i] = 0;
}

int CRYPTO_memcmp(const void *a, const void *b, size_t len) {
    return memcmp(a, b, len);
}
