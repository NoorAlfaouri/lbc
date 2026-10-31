/* User-level API contract tests. Link against the future public implementation. */
#define _POSIX_C_SOURCE 200809L
#include "../lbc.h"

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    static const unsigned char source[] =
        "public API roundtrip\0with binary\xff bytes\n";
    void *archive = NULL, *restored = NULL;
    size_t archive_size = 0, restored_size = 0;

    assert(lbc_compress(source, sizeof(source), 4096,
                        &archive, &archive_size) == LBC_OK);
    assert(archive != NULL && archive_size != 0);
    assert(lbc_decompress(archive, archive_size,
                          &restored, &restored_size) == LBC_OK);
    assert(restored_size == sizeof(source));
    assert(memcmp(restored, source, sizeof(source)) == 0);
    lbc_free(restored);
    lbc_free(archive);

    /* Corrupt input must return control and a status, never terminate host. */
    {
        static const unsigned char malformed[] = { 'N', 'O', 'P', 'E' };
        restored = (void *)(uintptr_t)1;
        restored_size = 123;
        assert(lbc_decompress(malformed, sizeof(malformed),
                             &restored, &restored_size) != LBC_OK);
        assert(restored == NULL && restored_size == 0);
    }
    {
        static const unsigned char malformed[] = { 'x', 'x', 'x', 'x', 4 };
        for (unsigned i = 0; i < 100; ++i) {
            restored = (void *)(uintptr_t)1;
            restored_size = 123;
            assert(lbc_decompress(malformed, sizeof(malformed), &restored,
                                  &restored_size) != LBC_OK);
            assert(restored == NULL && restored_size == 0);
        }
    }

    /* Failures leave ownership with the caller only for previously returned
       buffers; output slots are reset and can safely be reused. */
    archive = (void *)(uintptr_t)1;
    archive_size = 123;
    assert(lbc_compress(NULL, 1, 4096, &archive, &archive_size) != LBC_OK);
    assert(archive == NULL && archive_size == 0);

    /* Existing file destinations must remain untouched. */
    {
        char path[] = "/tmp/lbc-api-existing-XXXXXX";
        const unsigned char marker[] = { 0x51, 0x00, 0xa7 };
        unsigned char observed[sizeof(marker)];
        int fd = mkstemp(path);
        assert(fd >= 0);
        assert(write(fd, marker, sizeof(marker)) == (ssize_t)sizeof(marker));
        assert(close(fd) == 0);
        assert(lbc_compress_file("unused-source", path, 4096) == LBC_ERROR_EXISTS);
        fd = open(path, O_RDONLY);
        assert(fd >= 0);
        assert(read(fd, observed, sizeof(observed)) == (ssize_t)sizeof(observed));
        assert(close(fd) == 0);
        assert(memcmp(marker, observed, sizeof(marker)) == 0);
        assert(unlink(path) == 0);
    }
    assert(strcmp(lbc_status_string(LBC_OK), "") != 0);
    puts("public LBC API tests passed");
    return 0;
}
