// Account-store parser harness.
//
// Feeds a file straight into auth_store_parse(), the single parser targeted by
// the memory-safety / SMT / fuzzing analysis. Use it as an AFL/libFuzzer seed
// driver, or just to reproduce a crafted input.
//
// Usage: wschat_fuzz_store <file>
#include <stdio.h>
#include <stdlib.h>
#include "auth.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 2;
    }

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 2; }
    long sz = ftell(f);
    if (sz < 0) sz = 0;
    rewind(f);

    unsigned char *buf = (unsigned char *)malloc((size_t)sz);
    if (!buf && sz > 0) { fclose(f); return 2; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    int rc = auth_store_parse(buf, rd);
    printf("auth_store_parse -> rc=%d accounts=%d\n", rc, auth_num_accounts());

    free(buf);
    return 0;
}
