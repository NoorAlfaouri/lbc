#ifndef LBC_H_INCLUDED
#define LBC_H_INCLUDED

/*
 * LBC public API draft (ABI version 1). This header declares the intended
 * contract; the current command-line implementation does not yet implement
 * these symbols. Do not infer codec availability from inclusion success.
 */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LBC_ABI_VERSION 1u
#define LBC_MAX_INPUT_BYTES ((size_t)600u * 1024u * 1024u)
#define LBC_MAX_BLOCKS 1000000u
#define LBC_DEFAULT_CHUNK_BYTES (8u * 1024u * 1024u)

typedef enum lbc_status {
    LBC_OK = 0,
    LBC_ERROR_ARGUMENT,
    LBC_ERROR_LIMIT,
    LBC_ERROR_FORMAT,
    LBC_ERROR_IO,
    LBC_ERROR_MEMORY,
    LBC_ERROR_EXISTS,
    LBC_ERROR_UNSUPPORTED,
    LBC_ERROR_INTERNAL
} lbc_status;

/*
 * On success, *output is a library-allocated buffer of *output_size bytes.
 * Release it with lbc_free (never free it with a different allocator).
 * On failure, outputs are set to NULL and 0 where their pointers are valid.
 * Input is borrowed only for the duration of the call and is never modified.
 * A NULL input is valid only when input_size is zero. No function prints or
 * exits the host process. Calls may run concurrently; callers must not mutate
 * an input buffer until the call returns.
 */
lbc_status lbc_compress(const void *input, size_t input_size,
                        size_t chunk_size,
                        void **output, size_t *output_size);
lbc_status lbc_decompress(const void *archive, size_t archive_size,
                          void **output, size_t *output_size);
void lbc_free(void *buffer);

/* File helpers: fail with LBC_ERROR_EXISTS if destination already exists;
 * never truncate/replace it. Source and destination paths are borrowed. */
lbc_status lbc_compress_file(const char *source_path,
                             const char *archive_path,
                             size_t chunk_size);
lbc_status lbc_decompress_file(const char *archive_path,
                               const char *destination_path);

/* Borrowed stable diagnostic text; never NULL. Not intended for parsing. */
const char *lbc_status_string(lbc_status status);

#ifdef __cplusplus
}
#endif
#endif
