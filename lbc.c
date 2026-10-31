#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <setjmp.h>
#include <utime.h>
#include "lbc.h"

#define MIB (1024ULL * 1024ULL)
#define MAX_INPUT (600ULL * MIB)
#define MAX_BLOCKS 1000000U
#define DEFAULT_CHUNK (8U * 1024U * 1024U)
#define HUFFMAN_HEADER_BYTES 2048ULL
#define MAX_LZ_CHUNK (8U * 1024U * 1024U)
#define MAX_LZ_TOKEN_BYTES (2U * MAX_LZ_CHUNK + 16U)
#define MAX_BWT_CHUNK 32768U
#define MAX_BWT_TOKEN_BYTES (2U * MAX_BWT_CHUNK + 16U)
#define SHA_BLOCK 64U

/* All compression, deduplication, and SHA-256 logic below is implemented here. */
typedef struct {
    uint32_t state[8];
    uint64_t bit_length;
    uint8_t block[SHA_BLOCK];
    size_t used;
} Sha256;

typedef struct {
    uint64_t frequency;
    int left;
    int right;
    int symbol;
} HuffNode;

typedef struct {
    uint64_t hash;
    uint32_t id;
    uint8_t used;
} HashSlot;

typedef struct {
    uint64_t offset;
    uint32_t length;
} UniqueBlock;

typedef struct {
    uint32_t id;
    uint32_t count;
} Run;

typedef struct {
    uint64_t code[256];
    uint8_t length[256];
} HuffCodes;

static _Thread_local char *owned_paths[8];
static _Thread_local size_t owned_count;
static _Thread_local char *api_dir;
static _Thread_local uint32_t current_chunk_setting = DEFAULT_CHUNK;
static _Thread_local jmp_buf *api_jump;
static _Thread_local int api_status;
static _Thread_local int quiet_api;
static _Thread_local int opt_force = 0;
static _Thread_local int opt_test = 0;
static _Thread_local int opt_level = 9;
#ifndef LBC_NO_MAIN
static _Thread_local int opt_verbose = 0;
#endif
static _Thread_local unsigned temp_serial;
/* Every resource that may outlive a failing frame is owned by the current
   API invocation. TLS keeps simultaneous calls independent. */
static _Thread_local void *api_allocations[65536];
static _Thread_local size_t api_allocation_count;
static _Thread_local FILE *api_streams[64];
static _Thread_local size_t api_stream_count;
static _Thread_local int api_tracking;
static void fail(const char *message);
static void cleanup_owned(void);
static void api_free(void *p);

static void *api_malloc(size_t n) {
    void *p = malloc(n);
    if (p && api_tracking) {
        if (api_allocation_count == sizeof(api_allocations)/sizeof(api_allocations[0])) {
            free(p); fail("too many allocations");
        }
        api_allocations[api_allocation_count++] = p;
    }
    return p;
}
static void *api_calloc(size_t n, size_t size) {
    void *p = calloc(n, size);
    if (p && api_tracking) {
        if (api_allocation_count == sizeof(api_allocations)/sizeof(api_allocations[0])) {
            free(p); fail("too many allocations");
        }
        api_allocations[api_allocation_count++] = p;
    }
    return p;
}
static __attribute__((unused)) void *api_realloc(void *p, size_t n) {
    void *new_p = realloc(p, n);
    if (new_p && api_tracking) {
        if (p != NULL) {
            for (size_t i = api_allocation_count; i > 0; --i) {
                if (api_allocations[i - 1] == p) {
                    api_allocations[i - 1] = new_p;
                    return new_p;
                }
            }
        }
        if (api_allocation_count == sizeof(api_allocations)/sizeof(api_allocations[0])) {
            free(new_p); fail("too many allocations");
        }
        api_allocations[api_allocation_count++] = new_p;
    }
    return new_p;
}
static void api_free(void *p) {
    if (p && api_tracking) {
        for (size_t i = api_allocation_count; i > 0; --i) {
            if (api_allocations[i - 1] == p) {
                api_allocations[i - 1] = api_allocations[--api_allocation_count];
                api_allocations[api_allocation_count] = NULL;
                break;
            }
        }
    }
    free(p);
}
static FILE *api_track_stream(FILE *f) {
    if (f && api_tracking) {
        if (api_stream_count == sizeof(api_streams)/sizeof(api_streams[0])) { fclose(f); fail("too many open files"); }
        api_streams[api_stream_count++] = f;
    }
    return f;
}
static FILE *api_fopen(const char *path, const char *mode) {
    return api_track_stream(fopen(path, mode));
}
static int api_fclose(FILE *f) {
    if (api_tracking) {
        for (size_t i = api_stream_count; i > 0; --i) {
            if (api_streams[i - 1] == f) {
                api_streams[i - 1] = api_streams[--api_stream_count];
                api_streams[api_stream_count] = NULL;
                break;
            }
        }
    }
    return fclose(f);
}
static void cleanup_api_resources(void) {
    while (api_stream_count) (void)fclose(api_streams[--api_stream_count]);
    cleanup_owned();
    while (api_allocation_count) free(api_allocations[--api_allocation_count]);
    api_tracking = 0;
}

#define malloc api_malloc
#define calloc api_calloc
#define realloc api_realloc
#define free api_free
#define fclose api_fclose
#define fopen api_fopen

static void cleanup_owned(void) {
    for (size_t i = 0; i < owned_count; ++i) {
        if (owned_paths[i] != NULL) {
            (void)remove(owned_paths[i]);
            api_free(owned_paths[i]);
            owned_paths[i] = NULL;
        }
    }
    owned_count = 0;
    if (api_dir != NULL) {
        (void)rmdir(api_dir);
        api_free(api_dir);
        api_dir = NULL;
    }
}

static void fail(const char *message) {
    if (api_jump != NULL) {
        if (strstr(message, "existing output")) api_status = LBC_ERROR_EXISTS;
        else if (strstr(message, "unsupported")) api_status = LBC_ERROR_UNSUPPORTED;
        else if (strstr(message, "out of memory")) api_status = LBC_ERROR_MEMORY;
        else if (strstr(message, "limit") || strstr(message, "too many")) api_status = LBC_ERROR_LIMIT;
        else api_status = LBC_ERROR_FORMAT;
        longjmp(*api_jump, 1);
    }
    fprintf(stderr, "lbc: %s\n", message);
    exit(EXIT_FAILURE);
}

static void fail_errno(const char *operation) {
    if (api_jump != NULL) { api_status = errno == ENOMEM ? LBC_ERROR_MEMORY :
        (errno == EEXIST ? LBC_ERROR_EXISTS : LBC_ERROR_IO); longjmp(*api_jump, 1); }
    fprintf(stderr, "lbc: %s: %s\n", operation, strerror(errno));
    exit(EXIT_FAILURE);
}

static void register_owned(char *path) {
    if (owned_count >= sizeof(owned_paths) / sizeof(owned_paths[0]))
        fail("too many temporary files");
    owned_paths[owned_count++] = path;
}

static void release_owned(char *path, int remove_file) {
    for (size_t i = 0; i < owned_count; ++i) {
        if (owned_paths[i] == path) {
            if (remove_file && remove(path) != 0 && errno != ENOENT)
                fail_errno("removing temporary file");
            free(path);
            owned_paths[i] = owned_paths[owned_count - 1];
            owned_paths[owned_count - 1] = NULL;
            --owned_count;
            if (owned_count == 0 && api_dir != NULL) {
                (void)rmdir(api_dir);
                api_free(api_dir);
                api_dir = NULL;
            }
            return;
        }
    }
}

static char *temp_name(const char *output, const char *kind) {
    size_t n = strlen(output) + strlen(kind) + 48;
    char *path = malloc(n);
    if (path == NULL)
        fail("out of memory for temporary path");
    (void)snprintf(path, n, "%s.%s.%ld.%u", output, kind, (long)getpid(), ++temp_serial);
    return path;
}

static FILE *create_temp(const char *output, const char *kind, char **path_out) {
    char *path = temp_name(output, kind);
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) {
        free(path);
        fail_errno("creating project-local temporary file");
    }
    FILE *stream = fdopen(fd, "w+b");
    if (stream == NULL) {
        int saved = errno;
        (void)close(fd);
        (void)remove(path);
        free(path);
        errno = saved;
        fail_errno("opening temporary stream");
    }
    register_owned(path);
    *path_out = path;
    return stream;
}

static void copy_and_unlink(const char *src, const char *dst) {
    FILE *in = fopen(src, "rb");
    if (!in) fail_errno("opening source for copy");
    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); fail_errno("opening destination for copy"); }
    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            fclose(in); fclose(out); (void)remove(dst);
            fail_errno("writing destination copy");
        }
    }
    if (ferror(in)) { fclose(in); fclose(out); (void)remove(dst); fail_errno("reading source copy"); }
    if (fflush(out) != 0 || fsync(fileno(out)) != 0 || fclose(out) != 0) {
        fclose(in); (void)remove(dst); fail_errno("flushing destination copy");
    }
    fclose(in);
    (void)remove(src);
}

static void publish_temp(FILE *stream, char *temporary, const char *output) {
    if (fflush(stream) != 0 || fsync(fileno(stream)) != 0)
        fail_errno("flushing output");
    if (fclose(stream) != 0)
        fail_errno("closing output");
    if (opt_force) {
        if (rename(temporary, output) != 0) {
            if (errno == EXDEV) {
                copy_and_unlink(temporary, output);
            } else {
                (void)remove(output);
                if (rename(temporary, output) != 0) {
                    if (errno == EXDEV) {
                        copy_and_unlink(temporary, output);
                    } else {
                        fail_errno("publishing output with force");
                    }
                }
            }
        }
    } else {
        struct stat st;
        if (stat(output, &st) == 0) {
            fail("existing output file");
        }
        if (rename(temporary, output) != 0) {
            if (errno == EXDEV) {
                copy_and_unlink(temporary, output);
            } else {
                fail_errno("publishing output");
            }
        }
    }
    release_owned(temporary, 0);
}

static uint32_t rotate_right(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32U - n));
}

static const uint32_t sha_k[64] = {
    0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
    0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
    0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
    0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
    0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
    0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
    0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
    0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};

static void sha_transform(Sha256 *ctx, const uint8_t block[64]) {
    uint32_t w[64];
    for (unsigned i = 0; i < 16; ++i)
        w[i] = ((uint32_t)block[4*i] << 24) | ((uint32_t)block[4*i+1] << 16) |
               ((uint32_t)block[4*i+2] << 8) | (uint32_t)block[4*i+3];
    for (unsigned i = 16; i < 64; ++i) {
        uint32_t s0 = rotate_right(w[i-15], 7) ^ rotate_right(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotate_right(w[i-2], 17) ^ rotate_right(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=ctx->state[0], b=ctx->state[1], c=ctx->state[2], d=ctx->state[3];
    uint32_t e=ctx->state[4], f=ctx->state[5], g=ctx->state[6], h=ctx->state[7];
    for (unsigned i = 0; i < 64; ++i) {
        uint32_t s1 = rotate_right(e,6) ^ rotate_right(e,11) ^ rotate_right(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + s1 + ch + sha_k[i] + w[i];
        uint32_t s0 = rotate_right(a,2) ^ rotate_right(a,13) ^ rotate_right(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void sha_init(Sha256 *ctx) {
    static const uint32_t initial[8] = {
        0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
        0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U
    };
    memcpy(ctx->state, initial, sizeof(initial));
    ctx->bit_length = 0;
    ctx->used = 0;
}

static void sha_update(Sha256 *ctx, const uint8_t *data, size_t length) {
    ctx->bit_length += (uint64_t)length * 8U;
    while (length != 0) {
        size_t take = SHA_BLOCK - ctx->used;
        if (take > length) take = length;
        memcpy(ctx->block + ctx->used, data, take);
        ctx->used += take;
        data += take;
        length -= take;
        if (ctx->used == SHA_BLOCK) {
            sha_transform(ctx, ctx->block);
            ctx->used = 0;
        }
    }
}

static void sha_final(Sha256 *ctx, uint8_t digest[32]) {
    uint64_t original_bits = ctx->bit_length;
    ctx->block[ctx->used++] = 0x80U;
    if (ctx->used > 56U) {
        memset(ctx->block + ctx->used, 0, SHA_BLOCK - ctx->used);
        sha_transform(ctx, ctx->block);
        ctx->used = 0;
    }
    memset(ctx->block + ctx->used, 0, 56U - ctx->used);
    for (unsigned i = 0; i < 8; ++i)
        ctx->block[63U-i] = (uint8_t)(original_bits >> (8U*i));
    sha_transform(ctx, ctx->block);
    for (unsigned i = 0; i < 8; ++i) {
        digest[4U*i] = (uint8_t)(ctx->state[i] >> 24);
        digest[4U*i+1] = (uint8_t)(ctx->state[i] >> 16);
        digest[4U*i+2] = (uint8_t)(ctx->state[i] >> 8);
        digest[4U*i+3] = (uint8_t)ctx->state[i];
    }
}

static void sha_bytes(const uint8_t *data, size_t length, uint8_t digest[32]) {
    Sha256 ctx;
    sha_init(&ctx);
    sha_update(&ctx, data, length);
    sha_final(&ctx, digest);
}

static void print_digest(const uint8_t digest[32]) {
    for (unsigned i = 0; i < 32; ++i)
        printf("%02x", digest[i]);
}

static uint64_t fnv1a64(const uint8_t *data, size_t length) {
    uint64_t hash = 14695981039346656037ULL;
    for (size_t i = 0; i < length; ++i) {
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static void write_exact(FILE *stream, const void *data, size_t length) {
    if (length != 0 && fwrite(data, 1, length, stream) != length)
        fail_errno("writing stream");
}

static void read_exact(FILE *stream, void *data, size_t length) {
    if (length != 0 && fread(data, 1, length, stream) != length)
        fail("truncated compressed file");
}

static void put_u8(FILE *stream, uint8_t value) { write_exact(stream, &value, 1); }
static uint8_t get_u8(FILE *stream) { uint8_t x; read_exact(stream, &x, 1); return x; }

static void put_u32(FILE *stream, uint32_t value) {
    uint8_t b[4] = {(uint8_t)(value>>24),(uint8_t)(value>>16),(uint8_t)(value>>8),(uint8_t)value};
    write_exact(stream, b, sizeof(b));
}

static uint32_t get_u32(FILE *stream) {
    uint8_t b[4]; read_exact(stream, b, sizeof(b));
    return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];
}

static void put_u64(FILE *stream, uint64_t value) {
    uint8_t b[8];
    for (unsigned i = 0; i < 8; ++i) b[7U-i] = (uint8_t)(value>>(8U*i));
    write_exact(stream, b, sizeof(b));
}

static uint64_t get_u64(FILE *stream) {
    uint8_t b[8]; read_exact(stream, b, sizeof(b));
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value = (value<<8)|b[i];
    return value;
}

static uint8_t *load_file(const char *path, size_t *length) {
    FILE *stream = fopen(path, "rb");
    if (stream == NULL) fail_errno("opening input");
    if (fseeko(stream, 0, SEEK_END) != 0) fail_errno("seeking input");
    off_t end = ftello(stream);
    if (end < 0 || (uint64_t)end > MAX_INPUT) fail("input exceeds the 600 MiB safety limit");
    if (fseeko(stream, 0, SEEK_SET) != 0) fail_errno("rewinding input");
    *length = (size_t)end;
    uint8_t *data = malloc(*length == 0 ? 1 : *length);
    if (data == NULL) fail("out of memory loading input");
    read_exact(stream, data, *length);
    if (fclose(stream) != 0) fail_errno("closing input");
    return data;
}

static void verify_new_output(const char *path) {
    if (opt_test) return;
    if (path == NULL) return;
    if (opt_force) return;
    if (access(path, F_OK) == 0) {
        if (api_tracking) api_status = LBC_ERROR_EXISTS;
        fail("refusing to overwrite an existing output file");
    }
    if (errno != ENOENT) fail_errno("checking output path");
}

static size_t next_power_of_two(size_t value) {
    size_t result = 1;
    while (result < value) {
        if (result > SIZE_MAX / 2) fail("hash table size overflow");
        result <<= 1;
    }
    return result;
}

static void build_huffman_tree(const uint64_t frequencies[256], HuffNode nodes[511], int *root_out, unsigned *symbols_out) {
    uint8_t active[511] = {0};
    unsigned active_count = 0;
    for (int symbol = 0; symbol < 256; ++symbol) {
        if (frequencies[symbol] != 0) {
            nodes[symbol].frequency = frequencies[symbol];
            nodes[symbol].left = -1;
            nodes[symbol].right = -1;
            nodes[symbol].symbol = symbol;
            active[symbol] = 1;
            ++active_count;
        }
    }
    *symbols_out = active_count;
    if (active_count == 0) { *root_out = -1; return; }
    int next = 256;
    while (active_count > 1) {
        int first = -1, second = -1;
        for (int i = 0; i < next; ++i) {
            if (!active[i]) continue;
            if (first < 0 || nodes[i].frequency < nodes[first].frequency ||
                (nodes[i].frequency == nodes[first].frequency && i < first)) {
                second = first;
                first = i;
            } else if (second < 0 || nodes[i].frequency < nodes[second].frequency ||
                       (nodes[i].frequency == nodes[second].frequency && i < second)) {
                second = i;
            }
        }
        if (first < 0 || second < 0 || next >= 511) fail("invalid Huffman tree construction");
        active[first] = 0;
        active[second] = 0;
        nodes[next].frequency = nodes[first].frequency + nodes[second].frequency;
        if (nodes[next].frequency < nodes[first].frequency) fail("Huffman frequency overflow");
        nodes[next].left = first;
        nodes[next].right = second;
        nodes[next].symbol = -1;
        active[next] = 1;
        ++next;
        --active_count;
    }
    for (int i = 0; i < next; ++i) if (active[i]) { *root_out = i; return; }
    fail("missing Huffman root");
}

static int assign_codes(const HuffNode nodes[511], int node, uint64_t path, unsigned depth, HuffCodes *codes) {
    if (nodes[node].symbol >= 0) {
        if (depth == 0 || depth > 56) return 0;
        codes->code[nodes[node].symbol] = path;
        codes->length[nodes[node].symbol] = (uint8_t)depth;
        return 1;
    }
    if (depth >= 56) return 0;
    return assign_codes(nodes, nodes[node].left, path << 1, depth + 1, codes) &&
           assign_codes(nodes, nodes[node].right, (path << 1) | 1U, depth + 1, codes);
}

static uint8_t *encode_huffman(const uint8_t *data, size_t length, const uint64_t frequencies[256],
                               uint64_t header_bytes, uint64_t *bit_count_out,
                               size_t *payload_length_out) {
    HuffNode nodes[511];
    int root;
    unsigned symbols;
    build_huffman_tree(frequencies, nodes, &root, &symbols);
    if (symbols < 2) return NULL;
    HuffCodes codes = {{0},{0}};
    if (!assign_codes(nodes, root, 0, 0, &codes)) return NULL;
    uint64_t bits = 0;
    for (unsigned symbol = 0; symbol < 256; ++symbol) {
        if (frequencies[symbol] != 0) {
            uint64_t add = frequencies[symbol] * codes.length[symbol];
            if (UINT64_MAX - bits < add) return NULL;
            bits += add;
        }
    }
    if (bits > UINT64_MAX - 7U) return NULL;
    uint64_t payload64 = (bits + 7U) / 8U;
    if (payload64 >= length || header_bytes >= length || payload64 >= length - header_bytes ||
        payload64 > SIZE_MAX)
        return NULL;
    size_t payload_length = (size_t)payload64;
    uint8_t *payload = malloc(payload_length == 0 ? 1 : payload_length);
    if (payload == NULL) fail("out of memory encoding Huffman block");
    uint64_t accumulator = 0;
    unsigned held = 0;
    size_t position = 0;
    for (size_t i = 0; i < length; ++i) {
        unsigned code_length = codes.length[data[i]];
        if (code_length == 0) fail("Huffman model does not contain an input symbol");
        if (held > 63U - code_length) {
            while (held >= 8U) {
                held -= 8U;
                payload[position++] = (uint8_t)(accumulator >> held);
                accumulator &= held == 0 ? 0 : ((1ULL << held) - 1ULL);
            }
        }
        accumulator = (accumulator << code_length) | codes.code[data[i]];
        held += code_length;
        while (held >= 8U) {
            held -= 8U;
            payload[position++] = (uint8_t)(accumulator >> held);
            accumulator &= held == 0 ? 0 : ((1ULL << held) - 1ULL);
        }
    }
    if (held != 0) payload[position++] = (uint8_t)(accumulator << (8U - held));
    if (position != payload_length) fail("internal Huffman bit count mismatch");
    *bit_count_out = bits;
    *payload_length_out = payload_length;
    return payload;
}

static uint32_t lz_hash3(const uint8_t *data, uint32_t table_size) {
    if (table_size == 65536U)
        return (uint16_t)(((uint32_t)data[0] * 251U + (uint32_t)data[1]) * 251U + data[2]);
    uint32_t key = ((uint32_t)data[0] << 16) | ((uint32_t)data[1] << 8) | data[2];
    return (key * 2654435761U) >> 12;
}

static void lz_insert(const uint8_t *data, uint32_t length, uint32_t position,
                      int32_t *heads, int32_t *previous, uint32_t table_size) {
    if (position + 2U >= length) return;
    uint32_t hash = lz_hash3(data + position, table_size);
    previous[position] = heads[hash];
    heads[hash] = (int32_t)position;
}

static void emit_varint(uint8_t *output, size_t *position, uint32_t value) {
    while (value >= 128U) {
        output[(*position)++] = (uint8_t)(value | 0x80U);
        value >>= 7;
    }
    output[(*position)++] = (uint8_t)value;
}

static unsigned varint_size(uint32_t value) {
    unsigned size = 1;
    while (value >= 128U) { value >>= 7; ++size; }
    return size;
}

static void put_varint(FILE *output, uint32_t value) {
    uint8_t bytes[5];
    size_t length = 0;
    emit_varint(bytes, &length, value);
    write_exact(output, bytes, length);
}

static uint32_t get_varint(FILE *input) {
    uint32_t value = 0;
    for (unsigned i = 0; i < 5U; ++i) {
        uint8_t byte = get_u8(input);
        if (i == 4U && (byte & 0xf0U) != 0) fail("invalid sparse Huffman frequency");
        value |= (uint32_t)(byte & 0x7fU) << (7U * i);
        if ((byte & 0x80U) == 0) {
            if (i != 0 && byte == 0) fail("noncanonical sparse Huffman frequency");
            return value;
        }
    }
    fail("invalid sparse Huffman frequency");
    return 0;
}

static uint32_t find_match(const uint8_t *data, uint32_t length, uint32_t position,
                           uint32_t window, unsigned max_depth,
                           const int32_t *heads, const int32_t *previous,
                           uint32_t table_size, uint32_t *distance_out) {
    uint32_t best_length = 0;
    uint32_t best_distance = 0;
    if (position + 2U < length) {
        int32_t candidate = heads[lz_hash3(data + position, table_size)];
        unsigned searched = 0;
        uint32_t limit = length - position;
        while (candidate >= 0 && searched < max_depth) {
            uint32_t candidate_position = (uint32_t)candidate;
            uint32_t distance = position - candidate_position;
            if (distance > window) break;
            ++searched;
            if (best_length >= 5U && position + best_length < length) {
                if (data[candidate_position + best_length] != data[position + best_length]) {
                    candidate = previous[candidate];
                    continue;
                }
            }
            uint32_t matched = 0;
            while (matched < limit && data[candidate_position + matched] == data[position + matched])
                ++matched;
            if (matched > best_length) {
                best_length = matched;
                best_distance = distance;
                if (matched == limit) break;
            }
            candidate = previous[candidate];
        }
    }
    *distance_out = best_distance;
    return best_length;
}

static uint8_t *encode_lz_tokens(const uint8_t *data, uint32_t length, uint32_t window, size_t *token_length_out) {
    if (length > MAX_LZ_CHUNK) return NULL;
    uint32_t table_size = window > 32768U ? 1048576U : 65536U;
    uint8_t *tokens = malloc((size_t)length * 2U + 16U);
    int32_t *previous = malloc((size_t)length * sizeof(*previous));
    int32_t *heads = malloc((size_t)table_size * sizeof(*heads));
    if (tokens == NULL || previous == NULL || heads == NULL) fail("out of memory encoding LZ tokens");
    for (size_t i = 0; i < table_size; ++i) heads[i] = -1;
    unsigned max_depth = window > 32768U ? 256U : 128U;
    size_t token_position = 0;
    uint32_t position = 0;
    while (position < length) {
        uint32_t best_distance = 0;
        uint32_t best_length = find_match(data, length, position, window, max_depth,
                                          heads, previous, table_size, &best_distance);
        if (best_length >= 5U) {
            lz_insert(data, length, position, heads, previous, table_size);
            uint32_t next_distance = 0;
            uint32_t next_length = (position + 1U < length) ?
                find_match(data, length, position + 1U, window, max_depth,
                           heads, previous, table_size, &next_distance) : 0;
            if (next_length >= 5U &&
                (next_length > best_length + 1U || (best_length < 32U && next_length > best_length))) {
                uint8_t byte = data[position];
                if (byte == 0xffU) {
                    tokens[token_position++] = 0xffU;
                    tokens[token_position++] = 0U;
                } else {
                    tokens[token_position++] = byte;
                }
                tokens[token_position++] = 0xffU;
                tokens[token_position++] = 1U;
                emit_varint(tokens, &token_position, next_length);
                emit_varint(tokens, &token_position, next_distance);
                for (uint32_t i = 1; i <= next_length; ++i) {
                    lz_insert(data, length, position + i, heads, previous, table_size);
                }
                position += 1U + next_length;
            } else {
                tokens[token_position++] = 0xffU;
                tokens[token_position++] = 1U;
                emit_varint(tokens, &token_position, best_length);
                emit_varint(tokens, &token_position, best_distance);
                for (uint32_t i = 1; i < best_length; ++i) {
                    lz_insert(data, length, position + i, heads, previous, table_size);
                }
                position += best_length;
            }
        } else {
            uint8_t byte = data[position];
            if (byte == 0xffU) {
                tokens[token_position++] = 0xffU;
                tokens[token_position++] = 0U;
            } else {
                tokens[token_position++] = byte;
            }
            lz_insert(data, length, position, heads, previous, table_size);
            ++position;
        }
    }
    free(previous);
    free(heads);
    *token_length_out = token_position;
    return tokens;
}

static int read_varint(const uint8_t *tokens, size_t token_length, size_t *position, uint32_t *value_out) {
    if (*position >= token_length) return 0;
    uint8_t b = tokens[*position];
    if (!(b & 0x80U)) {
        (*position)++;
        *value_out = b;
        return 1;
    }
    uint32_t value = 0;
    unsigned shift = 0;
    for (unsigned i = 0; i < 5U; ++i) {
        if (*position >= token_length) return 0;
        uint8_t byte = tokens[(*position)++];
        if (shift == 28U && (byte & 0x70U) != 0) return 0;
        value |= (uint32_t)(byte & 0x7fU) << shift;
        if ((byte & 0x80U) == 0) {
            *value_out = value;
            return 1;
        }
        shift += 7U;
    }
    return 0;
}

static int decode_lz_tokens(const uint8_t *tokens, size_t token_length, uint8_t *output, uint32_t raw_length) {
    size_t position = 0;
    uint32_t written = 0;
    while (position < token_length && written < raw_length) {
        const uint8_t *next_ff = memchr(tokens + position, 0xffU, token_length - position);
        size_t lit_len = next_ff ? (size_t)(next_ff - (tokens + position)) : (token_length - position);
        if (lit_len > 0) {
            if (lit_len > raw_length - written) return 0;
            memcpy(output + written, tokens + position, lit_len);
            written += (uint32_t)lit_len;
            position += lit_len;
            if (position >= token_length || written >= raw_length) break;
        }
        if (position >= token_length) return 0;
        position++;
        if (position >= token_length) return 0;
        uint8_t tag = tokens[position++];
        if (tag == 0U) {
            if (written >= raw_length) return 0;
            output[written++] = 0xffU;
        } else if (tag == 1U) {
            uint32_t match_length, distance;
            if (!read_varint(tokens, token_length, &position, &match_length) ||
                !read_varint(tokens, token_length, &position, &distance) ||
                match_length < 5U || distance == 0 || distance > written ||
                match_length > raw_length - written)
                return 0;

            if (distance == 1) {
                memset(output + written, output[written - 1], match_length);
            } else if (match_length <= distance) {
                memcpy(output + written, output + written - distance, match_length);
            } else if (distance >= 16) {
                uint8_t *dst = output + written;
                const uint8_t *src = dst - distance;
                uint32_t rem = match_length;
                while (rem >= 16) {
                    memcpy(dst, src, 16);
                    dst += 16;
                    src += 16;
                    rem -= 16;
                }
                if (rem > 0) {
                    memcpy(dst, src, rem);
                }
            } else {
                uint32_t copied = distance;
                memcpy(output + written, output + written - distance, copied);
                while (copied < match_length) {
                    uint32_t amount = match_length - copied;
                    if (amount > copied) amount = copied;
                    memcpy(output + written + copied, output + written, amount);
                    copied += amount;
                }
            }
            written += match_length;
        } else {
            return 0;
        }
    }
    return position == token_length && written == raw_length;
}

static uint8_t *bwt_transform(const uint8_t *data, uint32_t length, uint32_t *primary_out) {
    if (length == 0 || length > MAX_BWT_CHUNK) return NULL;
    size_t n = length;
    size_t count_capacity = n > 256U ? n : 256U;
    uint32_t *order = malloc(n * sizeof(*order));
    uint32_t *classes = malloc(n * sizeof(*classes));
    uint32_t *shifted = malloc(n * sizeof(*shifted));
    uint32_t *next_classes = malloc(n * sizeof(*next_classes));
    uint32_t *counts = malloc(count_capacity * sizeof(*counts));
    if (order == NULL || classes == NULL || shifted == NULL ||
        next_classes == NULL || counts == NULL)
        fail("out of memory building BWT transform");

    memset(counts, 0, 256U * sizeof(*counts));
    for (uint32_t i = 0; i < length; ++i) ++counts[data[i]];
    uint32_t total = 0;
    for (unsigned byte = 0; byte < 256U; ++byte) {
        uint32_t frequency = counts[byte];
        counts[byte] = total;
        total += frequency;
    }
    for (uint32_t i = 0; i < length; ++i) order[counts[data[i]]++] = i;

    uint32_t class_count = 1;
    classes[order[0]] = 0;
    for (uint32_t i = 1; i < length; ++i) {
        if (data[order[i]] != data[order[i - 1U]]) ++class_count;
        classes[order[i]] = class_count - 1U;
    }

    for (uint32_t span = 1U; span < length && class_count < length;) {
        for (uint32_t i = 0; i < length; ++i)
            shifted[i] = order[i] >= span ? order[i] - span : order[i] + length - span;
        memset(counts, 0, (size_t)class_count * sizeof(*counts));
        for (uint32_t i = 0; i < length; ++i) ++counts[classes[shifted[i]]];
        total = 0;
        for (uint32_t i = 0; i < class_count; ++i) {
            uint32_t frequency = counts[i];
            counts[i] = total;
            total += frequency;
        }
        for (uint32_t i = 0; i < length; ++i) {
            uint32_t position = shifted[i];
            order[counts[classes[position]]++] = position;
        }

        uint32_t new_class_count = 1;
        next_classes[order[0]] = 0;
        for (uint32_t i = 1; i < length; ++i) {
            uint32_t previous = order[i - 1U], current = order[i];
            uint32_t previous_next = previous + span;
            uint32_t current_next = current + span;
            if (previous_next >= length) previous_next -= length;
            if (current_next >= length) current_next -= length;
            if (classes[previous] != classes[current] ||
                classes[previous_next] != classes[current_next])
                ++new_class_count;
            next_classes[current] = new_class_count - 1U;
        }
        uint32_t *swap = classes;
        classes = next_classes;
        next_classes = swap;
        class_count = new_class_count;
        if (span > length / 2U) break;
        span *= 2U;
    }

    uint8_t *last_column = malloc(n);
    if (last_column == NULL) fail("out of memory storing BWT transform");
    *primary_out = 0;
    for (uint32_t i = 0; i < length; ++i) {
        uint32_t position = order[i];
        if (position == 0) *primary_out = i;
        last_column[i] = data[position == 0 ? length - 1U : position - 1U];
    }
    free(order);
    free(classes);
    free(shifted);
    free(next_classes);
    free(counts);
    return last_column;
}

static void emit_zero_run(uint8_t *tokens, size_t *position, uint32_t run_length) {
    if (run_length == 0) return;
    tokens[(*position)++] = 0;
    emit_varint(tokens, position, run_length);
}

static uint8_t *encode_bwt_mtf(const uint8_t *last_column, uint32_t length,
                               size_t *token_length_out) {
    uint8_t *tokens = malloc((size_t)length * 2U + 16U);
    if (tokens == NULL) fail("out of memory encoding BWT move-to-front data");
    uint8_t symbols[256];
    for (unsigned i = 0; i < 256U; ++i) symbols[i] = (uint8_t)i;
    size_t position = 0;
    uint32_t zero_run = 0;
    for (uint32_t i = 0; i < length; ++i) {
        unsigned rank = 0;
        while (symbols[rank] != last_column[i]) ++rank;
        if (rank == 0) {
            ++zero_run;
            continue;
        }
        emit_zero_run(tokens, &position, zero_run);
        zero_run = 0;
        tokens[position++] = (uint8_t)rank;
        uint8_t value = symbols[rank];
        memmove(symbols + 1, symbols, rank);
        symbols[0] = value;
    }
    emit_zero_run(tokens, &position, zero_run);
    *token_length_out = position;
    return tokens;
}

static int decode_bwt_tokens(const uint8_t *tokens, size_t token_length, uint32_t primary,
                             uint8_t *output, uint32_t raw_length) {
    if (raw_length == 0 || raw_length > MAX_BWT_CHUNK || primary >= raw_length) return 0;
    uint8_t *ranks = malloc(raw_length);
    uint8_t *last_column = malloc(raw_length);
    uint32_t *next = malloc((size_t)raw_length * sizeof(*next));
    if (ranks == NULL || last_column == NULL || next == NULL)
        fail("out of memory decoding BWT data");

    size_t position = 0;
    uint32_t written = 0;
    while (position < token_length && written < raw_length) {
        uint8_t rank = tokens[position++];
        if (rank == 0) {
            uint32_t run_length;
            if (!read_varint(tokens, token_length, &position, &run_length) ||
                run_length == 0 || run_length > raw_length - written) {
                free(ranks);
                free(last_column);
                free(next);
                return 0;
            }
            memset(ranks + written, 0, run_length);
            written += run_length;
        } else {
            ranks[written++] = rank;
        }
    }
    if (position != token_length || written != raw_length) {
        free(ranks);
        free(last_column);
        free(next);
        return 0;
    }

    uint8_t symbols[256];
    for (unsigned i = 0; i < 256U; ++i) symbols[i] = (uint8_t)i;
    for (uint32_t i = 0; i < raw_length; ++i) {
        unsigned rank = ranks[i];
        uint8_t value = symbols[rank];
        last_column[i] = value;
        memmove(symbols + 1, symbols, rank);
        symbols[0] = value;
    }
    free(ranks);

    uint32_t counts[256] = {0}, starts[256], seen[256] = {0};
    for (uint32_t i = 0; i < raw_length; ++i) ++counts[last_column[i]];
    uint32_t total = 0;
    for (unsigned byte = 0; byte < 256U; ++byte) {
        starts[byte] = total;
        total += counts[byte];
    }
    for (uint32_t i = 0; i < raw_length; ++i) {
        uint8_t byte = last_column[i];
        next[i] = starts[byte] + seen[byte]++;
    }
    uint32_t row = primary;
    for (uint32_t i = raw_length; i > 0; --i) {
        output[i - 1U] = last_column[row];
        row = next[row];
    }
    free(last_column);
    free(next);
    return 1;
}

#define RC_TOP (1U << 24)

typedef struct {
    uint64_t low;
    uint32_t range;
    uint32_t cache;
    uint32_t cache_size;
    uint8_t *buffer;
    size_t size;
    size_t capacity;
} RangeEncoder;

typedef struct {
    uint32_t code;
    uint32_t range;
    const uint8_t *buffer;
    size_t size;
    size_t pos;
} RangeDecoder;

static void rc_enc_init(RangeEncoder *rc, uint8_t *out, size_t cap) {
    rc->low = 0;
    rc->range = 0xFFFFFFFFU;
    rc->cache = 0;
    rc->cache_size = 1;
    rc->buffer = out;
    rc->size = 0;
    rc->capacity = cap;
}

static inline void rc_enc_shift(RangeEncoder *rc) {
    uint32_t carry = (uint32_t)(rc->low >> 32);
    uint32_t low_hi = (uint32_t)(rc->low >> 24);
    if (low_hi != 0xFF || carry != 0) {
        if (rc->size < rc->capacity) {
            rc->buffer[rc->size++] = (uint8_t)(rc->cache + carry);
        }
        for (; rc->cache_size > 1; rc->cache_size--) {
            if (rc->size < rc->capacity) {
                rc->buffer[rc->size++] = (uint8_t)(0xFF + carry);
            }
        }
        rc->cache = (uint8_t)low_hi;
        rc->cache_size = 1;
    } else {
        rc->cache_size++;
    }
    rc->low = (uint32_t)(rc->low << 8);
}

static inline void rc_enc_renorm(RangeEncoder *rc) {
    while (rc->range < RC_TOP) {
        rc->range <<= 8;
        rc_enc_shift(rc);
    }
}

static inline void rc_encode(RangeEncoder *rc, uint32_t cum_freq, uint32_t freq, uint32_t total) {
    rc->range /= total;
    rc->low += (uint64_t)cum_freq * rc->range;
    rc->range *= freq;
    rc_enc_renorm(rc);
}

static void rc_enc_flush(RangeEncoder *rc) {
    for (int i = 0; i < 5; ++i) {
        rc_enc_shift(rc);
    }
}

static inline uint8_t rc_dec_byte(RangeDecoder *rc) {
    return rc->pos < rc->size ? rc->buffer[rc->pos++] : 0;
}

static void rc_dec_init(RangeDecoder *rc, const uint8_t *in, size_t in_len) {
    rc->code = 0;
    rc->range = 0xFFFFFFFFU;
    rc->buffer = in;
    rc->size = in_len;
    rc->pos = 0;
    rc_dec_byte(rc);
    for (int i = 0; i < 4; ++i) {
        rc->code = (rc->code << 8) | rc_dec_byte(rc);
    }
}

static inline void rc_dec_renorm(RangeDecoder *rc) {
    while (rc->range < RC_TOP) {
        rc->code = (rc->code << 8) | rc_dec_byte(rc);
        rc->range <<= 8;
        if (rc->range == 0) rc->range = 1;
    }
}

static inline uint32_t rc_get_cum_freq(RangeDecoder *rc, uint32_t total) {
    if (rc->range < total) rc->range = total;
    rc->range /= total;
    uint32_t val = rc->code / rc->range;
    return val >= total ? total - 1 : val;
}

static inline void rc_decode(RangeDecoder *rc, uint32_t cum_freq, uint32_t freq) {
    rc->code -= cum_freq * rc->range;
    rc->range *= freq;
    rc_dec_renorm(rc);
}

#define RC_MODEL_MAX_TOTAL 8192U

typedef struct {
    uint16_t tree[257];
    uint16_t freq[256];
    uint32_t total;
} AdaptiveModel256;

static void model256_init(AdaptiveModel256 *m) {
    m->total = 256;
    for (int i = 0; i < 256; ++i) {
        m->freq[i] = 1;
    }
    for (int i = 1; i <= 256; ++i) {
        m->tree[i] = (uint16_t)(i & (-i));
    }
}

static inline uint32_t model256_cum_freq(const AdaptiveModel256 *m, int symbol) {
    uint32_t sum = 0;
    for (int i = symbol; i > 0; i -= i & (-i)) {
        sum += m->tree[i];
    }
    return sum;
}

static inline int model256_find_symbol(const AdaptiveModel256 *m, uint32_t cum,
                                      uint32_t *cum_out, uint32_t *freq_out) {
    int idx = 0;
    for (int step = 128; step > 0; step >>= 1) {
        if (m->tree[idx + step] <= cum) {
            idx += step;
            cum -= m->tree[idx];
        }
    }
    *cum_out = model256_cum_freq(m, idx);
    *freq_out = m->freq[idx];
    return idx;
}

static void model256_rescale(AdaptiveModel256 *m) {
    m->total = 0;
    for (int i = 0; i < 256; ++i) {
        m->freq[i] = (uint16_t)((m->freq[i] + 1U) >> 1);
        m->total += m->freq[i];
    }
    memset(m->tree, 0, sizeof(m->tree));
    for (int i = 0; i < 256; ++i) {
        uint16_t f = m->freq[i];
        for (int j = i + 1; j <= 256; j += j & (-j)) {
            m->tree[j] += f;
        }
    }
}

static inline void model256_update(AdaptiveModel256 *m, int symbol) {
    m->freq[symbol]++;
    m->total++;
    for (int i = symbol + 1; i <= 256; i += i & (-i)) {
        m->tree[i]++;
    }
    if (m->total >= RC_MODEL_MAX_TOTAL) {
        model256_rescale(m);
    }
}

static uint8_t *encode_range_order0(const uint8_t *data, size_t length, size_t *out_len) {
    size_t cap = length + 64;
    uint8_t *out = malloc(cap);
    if (!out) return NULL;
    RangeEncoder rc;
    rc_enc_init(&rc, out, cap);
    AdaptiveModel256 m;
    model256_init(&m);
    for (size_t i = 0; i < length; ++i) {
        int s = data[i];
        uint32_t cum = model256_cum_freq(&m, s);
        uint32_t freq = m.freq[s];
        rc_encode(&rc, cum, freq, m.total);
        model256_update(&m, s);
        if (rc.size >= length) {
            free(out);
            return NULL;
        }
    }
    rc_enc_flush(&rc);
    if (rc.size >= length) {
        free(out);
        return NULL;
    }
    *out_len = rc.size;
    return out;
}

static uint8_t *encode_range_order1(const uint8_t *data, size_t length, size_t *out_len) {
    if (length == 0) return NULL;
    size_t cap = length + 64;
    uint8_t *out = malloc(cap);
    AdaptiveModel256 *ctxs = malloc(256 * sizeof(AdaptiveModel256));
    if (!out || !ctxs) {
        free(out);
        free(ctxs);
        return NULL;
    }
    for (int i = 0; i < 256; ++i) model256_init(&ctxs[i]);
    RangeEncoder rc;
    rc_enc_init(&rc, out, cap);
    int ctx = 0;
    for (size_t i = 0; i < length; ++i) {
        int s = data[i];
        uint32_t cum = model256_cum_freq(&ctxs[ctx], s);
        uint32_t freq = ctxs[ctx].freq[s];
        rc_encode(&rc, cum, freq, ctxs[ctx].total);
        model256_update(&ctxs[ctx], s);
        ctx = s;
        if (rc.size >= length) {
            free(out);
            free(ctxs);
            return NULL;
        }
    }
    rc_enc_flush(&rc);
    free(ctxs);
    if (rc.size >= length) {
        free(out);
        return NULL;
    }
    *out_len = rc.size;
    return out;
}

static int decode_range_order0(const uint8_t *in, size_t in_len, uint8_t *out, size_t raw_length) {
    RangeDecoder rc;
    rc_dec_init(&rc, in, in_len);
    AdaptiveModel256 m;
    model256_init(&m);
    for (size_t i = 0; i < raw_length; ++i) {
        uint32_t target = rc_get_cum_freq(&rc, m.total);
        uint32_t cum = 0, freq = 0;
        int s = model256_find_symbol(&m, target, &cum, &freq);
        rc_decode(&rc, cum, freq);
        model256_update(&m, s);
        out[i] = (uint8_t)s;
    }
    return 1;
}

static int decode_range_order1(const uint8_t *in, size_t in_len, uint8_t *out, size_t raw_length) {
    RangeDecoder rc;
    rc_dec_init(&rc, in, in_len);
    AdaptiveModel256 *ctxs = malloc(256 * sizeof(AdaptiveModel256));
    if (!ctxs) return 0;
    for (int i = 0; i < 256; ++i) model256_init(&ctxs[i]);
    int ctx = 0;
    for (size_t i = 0; i < raw_length; ++i) {
        uint32_t target = rc_get_cum_freq(&rc, ctxs[ctx].total);
        uint32_t cum = 0, freq = 0;
        int s = model256_find_symbol(&ctxs[ctx], target, &cum, &freq);
        rc_decode(&rc, cum, freq);
        model256_update(&ctxs[ctx], s);
        ctx = s;
        out[i] = (uint8_t)s;
    }
    free(ctxs);
    return 1;
}

static inline int lbc_has_x86_calls(const uint8_t *d, size_t n) {
    if (n < 512) return 0;
    size_t sample = n > 65536 ? 65536 : n;
    size_t calls = 0;
    for (size_t i = 0; i + 5 <= sample; ++i) {
        if ((d[i] & 0xFE) == 0xE8) {
            int32_t v = (int32_t)((uint32_t)d[i+1] | ((uint32_t)d[i+2] << 8) |
                                  ((uint32_t)d[i+3] << 16) | ((uint32_t)d[i+4] << 24));
            if (v >= -(1 << 20) && v < (1 << 20)) {
                if (++calls >= 8) return 1;
            }
        }
    }
    return 0;
}

static inline void lbc_bcj_x86_filter(uint8_t *data, size_t size, int encode) {
    if (size < 5) return;
    for (size_t i = 0; i + 5 <= size; ) {
        if ((data[i] & 0xFE) == 0xE8) {
            int32_t v = (int32_t)((uint32_t)data[i+1] | ((uint32_t)data[i+2] << 8) |
                                  ((uint32_t)data[i+3] << 16) | ((uint32_t)data[i+4] << 24));
            if (v >= -(1 << 24) && v < (1 << 24)) {
                uint32_t pos = (uint32_t)(i + 5);
                uint32_t u = (uint32_t)(v + (1 << 24));
                u = encode ? (u + pos) & 0x1FFFFFFu : (u - pos) & 0x1FFFFFFu;
                int32_t w = (int32_t)u - (1 << 24);
                data[i+1] = (uint8_t)w;
                data[i+2] = (uint8_t)((uint32_t)w >> 8);
                data[i+3] = (uint8_t)((uint32_t)w >> 16);
                data[i+4] = (uint8_t)((uint32_t)w >> 24);
            }
            i += 5;
        } else {
            i++;
        }
    }
}

/* LBC-BitLZ: Context-Adaptive Binary Range Coder over LZ with Repeat Distances */

typedef struct {
    uint32_t x1;
    uint32_t x2;
    uint8_t *out;
    size_t pos;
    size_t cap;
} BitLZRCEnc;

typedef struct {
    uint32_t x1;
    uint32_t x2;
    uint32_t x;
    const uint8_t *in;
    size_t pos;
    size_t len;
} BitLZRCDec;

static void bitlz_rc_enc_init(BitLZRCEnc *rc, uint8_t *out, size_t cap) {
    rc->x1 = 0;
    rc->x2 = 0xFFFFFFFFU;
    rc->out = out;
    rc->pos = 0;
    rc->cap = cap;
}

static inline void bitlz_rc_enc_bit(BitLZRCEnc *rc, uint16_t *prob, int bit) {
    uint32_t bound = rc->x1 + (uint32_t)(((uint64_t)(rc->x2 - rc->x1) * (*prob)) >> 16);
    if (bit) {
        rc->x2 = bound;
        *prob += (uint16_t)((65536U - *prob) >> 5);
    } else {
        rc->x1 = bound + 1;
        *prob -= (uint16_t)(*prob >> 5);
    }
    while (((rc->x1 ^ rc->x2) & 0xFF000000U) == 0) {
        if (rc->pos < rc->cap) rc->out[rc->pos++] = (uint8_t)(rc->x2 >> 24);
        rc->x1 <<= 8;
        rc->x2 = (rc->x2 << 8) | 0xFFU;
    }
}

static inline void bitlz_rc_enc_direct(BitLZRCEnc *rc, uint32_t val, int bits) {
    for (int i = bits - 1; i >= 0; --i) {
        uint16_t p = 32768U;
        bitlz_rc_enc_bit(rc, &p, (val >> i) & 1);
    }
}

static void bitlz_rc_enc_flush(BitLZRCEnc *rc) {
    if (rc->pos < rc->cap) rc->out[rc->pos++] = (uint8_t)(rc->x1 >> 24);
    for (int i = 0; i < 3; ++i) {
        if (rc->pos < rc->cap) rc->out[rc->pos++] = 0xFF;
    }
}

static inline uint8_t bitlz_rc_next_byte(BitLZRCDec *rc) {
    return rc->pos < rc->len ? rc->in[rc->pos++] : 0xFF;
}

static void bitlz_rc_dec_init(BitLZRCDec *rc, const uint8_t *in, size_t len) {
    rc->x1 = 0;
    rc->x2 = 0xFFFFFFFFU;
    rc->x = 0;
    rc->in = in;
    rc->pos = 0;
    rc->len = len;
    for (int i = 0; i < 4; ++i) {
        rc->x = (rc->x << 8) | bitlz_rc_next_byte(rc);
    }
}

static inline int bitlz_rc_dec_bit(BitLZRCDec *rc, uint16_t *prob) {
    uint32_t bound = rc->x1 + (uint32_t)(((uint64_t)(rc->x2 - rc->x1) * (*prob)) >> 16);
    int bit = (rc->x <= bound);
    if (bit) {
        rc->x2 = bound;
        *prob += (uint16_t)((65536U - *prob) >> 5);
    } else {
        rc->x1 = bound + 1;
        *prob -= (uint16_t)(*prob >> 5);
    }
    while (((rc->x1 ^ rc->x2) & 0xFF000000U) == 0) {
        rc->x1 <<= 8;
        rc->x2 = (rc->x2 << 8) | 0xFFU;
        uint8_t b = rc->pos < rc->len ? rc->in[rc->pos++] : 0xFF;
        rc->x = (rc->x << 8) | b;
    }
    return bit;
}

static inline uint32_t bitlz_rc_dec_direct(BitLZRCDec *rc, int bits) {
    uint32_t val = 0;
    for (int i = 0; i < bits; ++i) {
        uint16_t p = 32768U;
        int bit = bitlz_rc_dec_bit(rc, &p);
        val = (val << 1) | (uint32_t)bit;
    }
    return val;
}

static inline void bitlz_rc_enc_tree(BitLZRCEnc *rc, uint16_t *probs, int bits, uint32_t val) {
    uint32_t m = 1;
    for (int i = bits - 1; i >= 0; --i) {
        int b = (val >> i) & 1;
        bitlz_rc_enc_bit(rc, &probs[m], b);
        m = (m << 1) | (uint32_t)b;
    }
}

static inline uint32_t bitlz_rc_dec_tree(BitLZRCDec *rc, uint16_t *probs, int bits) {
    uint32_t m = 1;
    for (int i = 0; i < bits; ++i) {
        int b = bitlz_rc_dec_bit(rc, &probs[m]);
        m = (m << 1) | (uint32_t)b;
    }
    return m - (1U << bits);
}

static inline void bitlz_rc_enc_rev_tree(BitLZRCEnc *rc, uint16_t *probs, int bits, uint32_t val) {
    uint32_t m = 1;
    for (int i = 0; i < bits; ++i) {
        int b = (val >> i) & 1;
        bitlz_rc_enc_bit(rc, &probs[m], b);
        m = (m << 1) | (uint32_t)b;
    }
}

static inline uint32_t bitlz_rc_dec_rev_tree(BitLZRCDec *rc, uint16_t *probs, int bits) {
    uint32_t m = 1;
    uint32_t val = 0;
    for (int i = 0; i < bits; ++i) {
        int b = bitlz_rc_dec_bit(rc, &probs[m]);
        m = (m << 1) | (uint32_t)b;
        val |= ((uint32_t)b << i);
    }
    return val;
}

static inline int bitlz_state_next_literal(int s) { return s < 4 ? 0 : (s < 10 ? s - 3 : s - 6); }
static inline int bitlz_state_next_match(int s) { return s < 7 ? 7 : 10; }
static inline int bitlz_state_next_rep(int s) { return s < 7 ? 8 : 11; }
static inline int bitlz_state_next_short_rep(int s) { return s < 7 ? 9 : 11; }

typedef struct {
    uint16_t choice1;
    uint16_t choice2;
    uint16_t low[16][8];
    uint16_t mid[16][8];
    uint16_t high[256];
} BitLZLenCodec;

static void bitlz_len_codec_init(BitLZLenCodec *lc) {
    lc->choice1 = 32768U;
    lc->choice2 = 32768U;
    for (int i = 0; i < 16; ++i)
        for (int j = 0; j < 8; ++j) {
            lc->low[i][j] = 32768U;
            lc->mid[i][j] = 32768U;
        }
    for (int i = 0; i < 256; ++i) lc->high[i] = 32768U;
}

static inline void bitlz_enc_len(BitLZRCEnc *rc, BitLZLenCodec *lc, uint32_t len, int pos_state) {
    len -= 2;
    if (len < 8) {
        bitlz_rc_enc_bit(rc, &lc->choice1, 0);
        bitlz_rc_enc_tree(rc, lc->low[pos_state], 3, len);
    } else if (len < 16) {
        bitlz_rc_enc_bit(rc, &lc->choice1, 1);
        bitlz_rc_enc_bit(rc, &lc->choice2, 0);
        bitlz_rc_enc_tree(rc, lc->mid[pos_state], 3, len - 8);
    } else {
        bitlz_rc_enc_bit(rc, &lc->choice1, 1);
        bitlz_rc_enc_bit(rc, &lc->choice2, 1);
        bitlz_rc_enc_tree(rc, lc->high, 8, len - 16);
    }
}

static inline uint32_t bitlz_dec_len(BitLZRCDec *rc, BitLZLenCodec *lc, int pos_state) {
    if (!bitlz_rc_dec_bit(rc, &lc->choice1)) {
        return 2 + bitlz_rc_dec_tree(rc, lc->low[pos_state], 3);
    }
    if (!bitlz_rc_dec_bit(rc, &lc->choice2)) {
        return 2 + 8 + bitlz_rc_dec_tree(rc, lc->mid[pos_state], 3);
    }
    return 2 + 16 + bitlz_rc_dec_tree(rc, lc->high, 8);
}

typedef struct {
    uint16_t is_match[12][16];
    uint16_t is_rep[12];
    uint16_t is_rep_g0[12];
    uint16_t is_rep_g1[12];
    uint16_t is_rep_g2[12];
    uint16_t is_rep0_long[12][16];
    uint16_t dist_slot[4][64];
    uint16_t dist_align[16];
    uint16_t dist_special[14][32];
    BitLZLenCodec len_codec;
    BitLZLenCodec rep_len_codec;
    uint16_t lit[64][768];
} BitLZModel;

static void bitlz_model_init(BitLZModel *m) {
    for (int i = 0; i < 12; ++i) {
        for (int j = 0; j < 16; ++j) {
            m->is_match[i][j] = 32768U;
            m->is_rep0_long[i][j] = 32768U;
        }
        m->is_rep[i] = 32768U;
        m->is_rep_g0[i] = 32768U;
        m->is_rep_g1[i] = 32768U;
        m->is_rep_g2[i] = 32768U;
    }
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 64; ++j)
            m->dist_slot[i][j] = 32768U;
    for (int i = 0; i < 16; ++i) m->dist_align[i] = 32768U;
    for (int i = 0; i < 14; ++i)
        for (int j = 0; j < 32; ++j)
            m->dist_special[i][j] = 32768U;
    bitlz_len_codec_init(&m->len_codec);
    bitlz_len_codec_init(&m->rep_len_codec);
    for (int i = 0; i < 64; ++i)
        for (int j = 0; j < 768; ++j)
            m->lit[i][j] = 32768U;
}

static inline int bitlz_get_dist_slot(uint32_t d0) {
    if (d0 < 4) return (int)d0;
    int n = 31 - __builtin_clz(d0);
    return (n << 1) | (int)((d0 >> (n - 1)) & 1);
}

#define BITLZ_HASH_BITS 18
#define BITLZ_HASH_SIZE (1U << BITLZ_HASH_BITS)

static inline uint32_t bitlz_hash4(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return (v * 2654435761U) >> (32 - BITLZ_HASH_BITS);
}

static inline uint8_t *encode_bit_lz(const uint8_t *in, size_t size, size_t *out_len) {
    if (size == 0) return NULL;
    size_t out_cap = size + 65536;
    uint8_t *out = malloc(out_cap);
    if (!out) return NULL;

    BitLZRCEnc rc;
    bitlz_rc_enc_init(&rc, out, out_cap);

    BitLZModel *m = malloc(sizeof(BitLZModel));
    if (!m) { free(out); return NULL; }
    bitlz_model_init(m);

    int32_t *head = malloc(BITLZ_HASH_SIZE * sizeof(int32_t));
    int32_t *prev = malloc(size * sizeof(int32_t));
    int32_t *head3 = malloc(65536 * sizeof(int32_t));
    if (!head || !prev || !head3) {
        free(m); free(out); free(head); free(prev); free(head3); return NULL;
    }
    for (size_t i = 0; i < BITLZ_HASH_SIZE; ++i) head[i] = -1;
    for (size_t i = 0; i < 65536; ++i) head3[i] = -1;

    uint32_t rep0 = 1, rep1 = 1, rep2 = 1, rep3 = 1;
    int state = 0;
    size_t pos = 0;

    while (pos < size) {
        int pos_state = (int)(pos & 3);
        uint8_t prev_byte = pos > 0 ? in[pos - 1] : 0;
        int lit_ctx = ((pos & 3) << 4) | (prev_byte >> 4);

        uint32_t best_rep_len = 0;
        int best_rep_idx = -1;
        uint32_t reps[4] = {rep0, rep1, rep2, rep3};
        for (int r = 0; r < 4; ++r) {
            uint32_t d = reps[r];
            if (d <= pos) {
                uint32_t l = 0;
                while (pos + l < size && l < 273 && in[pos + l] == in[pos + l - d]) l++;
                if (l >= 2 && l > best_rep_len) {
                    best_rep_len = l;
                    best_rep_idx = r;
                }
            }
        }

        uint32_t best_match_len = 0;
        uint32_t best_match_dist = 0;
        if (pos + 3 <= size) {
            uint32_t v3 = (uint32_t)in[pos] | ((uint32_t)in[pos+1] << 8) | ((uint32_t)in[pos+2] << 16);
            uint32_t h3 = (v3 * 2654435761U) >> 16;
            int32_t cand3 = head3[h3];
            head3[h3] = (int32_t)pos;
            if (cand3 >= 0) {
                uint32_t d = (uint32_t)(pos - cand3);
                if (d < 65536) {
                    uint32_t l = 0;
                    while (pos + l < size && l < 273 && in[pos + l] == in[cand3 + l]) l++;
                    if (l >= 3) {
                        best_match_len = l;
                        best_match_dist = d;
                    }
                }
            }
        }
        if (pos + 4 <= size) {
            uint32_t h = bitlz_hash4(in + pos);
            int32_t cand = head[h];
            int chain_limit = 256;
            while (cand >= 0 && chain_limit-- > 0) {
                uint32_t d = (uint32_t)(pos - cand);
                if (d > 1048576) break;
                uint32_t l = 0;
                while (pos + l < size && l < 273 && in[pos + l] == in[cand + l]) l++;
                if (l >= 3 && l > best_match_len) {
                    best_match_len = l;
                    best_match_dist = d;
                    if (l >= 128) break;
                }
                cand = prev[cand];
            }
            prev[pos] = head[h];
            head[h] = (int32_t)pos;
        }

        if (best_rep_len >= 2 && best_rep_len >= best_match_len) {
            bitlz_rc_enc_bit(&rc, &m->is_match[state][pos_state], 1);
            bitlz_rc_enc_bit(&rc, &m->is_rep[state], 1);
            if (best_rep_idx == 0) {
                bitlz_rc_enc_bit(&rc, &m->is_rep_g0[state], 0);
                bitlz_rc_enc_bit(&rc, &m->is_rep0_long[state][pos_state], 1);
            } else {
                bitlz_rc_enc_bit(&rc, &m->is_rep_g0[state], 1);
                if (best_rep_idx == 1) {
                    bitlz_rc_enc_bit(&rc, &m->is_rep_g1[state], 0);
                    uint32_t tmp = rep1; rep1 = rep0; rep0 = tmp;
                } else if (best_rep_idx == 2) {
                    bitlz_rc_enc_bit(&rc, &m->is_rep_g1[state], 1);
                    bitlz_rc_enc_bit(&rc, &m->is_rep_g2[state], 0);
                    uint32_t tmp = rep2; rep2 = rep1; rep1 = rep0; rep0 = tmp;
                } else {
                    bitlz_rc_enc_bit(&rc, &m->is_rep_g1[state], 1);
                    bitlz_rc_enc_bit(&rc, &m->is_rep_g2[state], 1);
                    uint32_t tmp = rep3; rep3 = rep2; rep2 = rep1; rep1 = rep0; rep0 = tmp;
                }
            }
            bitlz_enc_len(&rc, &m->rep_len_codec, best_rep_len, pos_state);
            state = bitlz_state_next_rep(state);
            pos += best_rep_len;
        } else if (best_match_len >= 3) {
            int take_literal = 0;
            if (pos + 1 < size) {
                for (int r = 0; r < 4; ++r) {
                    uint32_t d = reps[r];
                    if (d <= pos + 1) {
                        uint32_t l = 0;
                        while (pos + 1 + l < size && l < 273 && in[pos + 1 + l] == in[pos + 1 + l - d]) l++;
                        if (l >= 2 && l >= best_match_len) {
                            take_literal = 1;
                            break;
                        }
                    }
                }
            }
            if (!take_literal && pos + 1 + 4 <= size && best_match_len < 64) {
                uint32_t h1 = bitlz_hash4(in + pos + 1);
                int32_t c1 = head[h1];
                int limit1 = 64;
                while (c1 >= 0 && limit1-- > 0) {
                    uint32_t l1 = 0;
                    while (pos + 1 + l1 < size && l1 < 273 && in[pos + 1 + l1] == in[c1 + l1]) l1++;
                    if (l1 > best_match_len + 1) {
                        take_literal = 1;
                        break;
                    }
                    c1 = prev[c1];
                }
            }
            if (take_literal) {
                bitlz_rc_enc_bit(&rc, &m->is_match[state][pos_state], 0);
                uint8_t cur = in[pos];
                uint16_t *probs = m->lit[lit_ctx];
                if (state < 7) {
                    bitlz_rc_enc_tree(&rc, probs, 8, cur);
                } else {
                    uint8_t match_byte = pos >= rep0 ? in[pos - rep0] : 0;
                    uint32_t node = 1;
                    int match_mode = 1;
                    for (int i = 7; i >= 0; --i) {
                        int bit = (cur >> i) & 1;
                        int match_bit = (match_byte >> i) & 1;
                        uint32_t sub_node = match_mode ? (256U + ((uint32_t)match_bit << 8) + node) : node;
                        bitlz_rc_enc_bit(&rc, &probs[sub_node % 768], bit);
                        node = (node << 1) | (uint32_t)bit;
                        if (match_mode && (bit != match_bit)) match_mode = 0;
                    }
                }
                state = bitlz_state_next_literal(state);
                pos++;
                continue;
            }

            bitlz_rc_enc_bit(&rc, &m->is_match[state][pos_state], 1);
            bitlz_rc_enc_bit(&rc, &m->is_rep[state], 0);
            bitlz_enc_len(&rc, &m->len_codec, best_match_len, pos_state);

            uint32_t d0 = best_match_dist - 1;
            int len_st = best_match_len < 6 ? (int)(best_match_len - 2) : 3;
            int slot = bitlz_get_dist_slot(d0);
            bitlz_rc_enc_tree(&rc, m->dist_slot[len_st], 6, slot);

            if (slot >= 4) {
                int footer_bits = (slot >> 1) - 1;
                uint32_t base = (2 | (slot & 1)) << footer_bits;
                uint32_t diff = d0 - base;
                if (slot < 14) {
                    bitlz_rc_enc_rev_tree(&rc, m->dist_special[slot], footer_bits, diff);
                } else {
                    bitlz_rc_enc_direct(&rc, diff >> 4, footer_bits - 4);
                    bitlz_rc_enc_rev_tree(&rc, m->dist_align, 4, diff & 15);
                }
            }

            rep3 = rep2;
            rep2 = rep1;
            rep1 = rep0;
            rep0 = best_match_dist;
            state = bitlz_state_next_match(state);
            pos += best_match_len;
        } else {
            if (pos >= rep0 && in[pos] == in[pos - rep0]) {
                bitlz_rc_enc_bit(&rc, &m->is_match[state][pos_state], 1);
                bitlz_rc_enc_bit(&rc, &m->is_rep[state], 1);
                bitlz_rc_enc_bit(&rc, &m->is_rep_g0[state], 0);
                bitlz_rc_enc_bit(&rc, &m->is_rep0_long[state][pos_state], 0);
                state = bitlz_state_next_short_rep(state);
                pos++;
                continue;
            }
            bitlz_rc_enc_bit(&rc, &m->is_match[state][pos_state], 0);
            uint8_t cur = in[pos];
            uint16_t *probs = m->lit[lit_ctx];
            if (state < 7) {
                bitlz_rc_enc_tree(&rc, probs, 8, cur);
            } else {
                uint8_t match_byte = pos >= rep0 ? in[pos - rep0] : 0;
                uint32_t node = 1;
                int match_mode = 1;
                for (int i = 7; i >= 0; --i) {
                    int bit = (cur >> i) & 1;
                    int match_bit = (match_byte >> i) & 1;
                    uint32_t sub_node = match_mode ? (256U + ((uint32_t)match_bit << 8) + node) : node;
                    bitlz_rc_enc_bit(&rc, &probs[sub_node % 768], bit);
                    node = (node << 1) | (uint32_t)bit;
                    if (match_mode && (bit != match_bit)) match_mode = 0;
                }
            }
            state = bitlz_state_next_literal(state);
            pos++;
        }

        if (rc.pos >= size) {
            free(prev); free(head); free(head3); free(m); free(out);
            return NULL;
        }
    }

    bitlz_rc_enc_flush(&rc);
    free(prev);
    free(head);
    free(head3);
    free(m);
    if (rc.pos >= size) {
        free(out);
        return NULL;
    }
    *out_len = rc.pos;
    return out;
}

static int decode_bit_lz(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len) {
    if (out_len == 0) return 1;
    BitLZRCDec rc;
    bitlz_rc_dec_init(&rc, in, in_len);

    BitLZModel *m = malloc(sizeof(BitLZModel));
    if (!m) return 0;
    bitlz_model_init(m);

    uint32_t rep0 = 1, rep1 = 1, rep2 = 1, rep3 = 1;
    int state = 0;
    size_t pos = 0;

    while (pos < out_len) {
        int pos_state = (int)(pos & 3);
        uint8_t prev_byte = pos > 0 ? out[pos - 1] : 0;
        int lit_ctx = ((pos & 3) << 4) | (prev_byte >> 4);

        if (!bitlz_rc_dec_bit(&rc, &m->is_match[state][pos_state])) {
            uint16_t *probs = m->lit[lit_ctx];
            uint8_t byte = 0;
            if (state < 7) {
                byte = (uint8_t)bitlz_rc_dec_tree(&rc, probs, 8);
            } else {
                uint8_t match_byte = pos >= rep0 ? out[pos - rep0] : 0;
                uint32_t node = 1;
                int match_mode = 1;
                for (int i = 7; i >= 0; --i) {
                    int match_bit = (match_byte >> i) & 1;
                    uint32_t sub_node = match_mode ? (256U + ((uint32_t)match_bit << 8) + node) : node;
                    int bit = bitlz_rc_dec_bit(&rc, &probs[sub_node % 768]);
                    node = (node << 1) | (uint32_t)bit;
                    if (match_mode && (bit != match_bit)) match_mode = 0;
                }
                byte = (uint8_t)(node - 256);
            }
            out[pos++] = byte;
            state = bitlz_state_next_literal(state);
        } else {
            uint32_t len = 0, dist = 0;
            if (bitlz_rc_dec_bit(&rc, &m->is_rep[state])) {
                if (!bitlz_rc_dec_bit(&rc, &m->is_rep_g0[state])) {
                    if (!bitlz_rc_dec_bit(&rc, &m->is_rep0_long[state][pos_state])) {
                        state = bitlz_state_next_short_rep(state);
                        if (pos < rep0) { free(m); return 0; }
                        out[pos] = out[pos - rep0];
                        pos++;
                        continue;
                    }
                    dist = rep0;
                } else {
                    if (!bitlz_rc_dec_bit(&rc, &m->is_rep_g1[state])) {
                        dist = rep1;
                        rep1 = rep0;
                        rep0 = dist;
                    } else {
                        if (!bitlz_rc_dec_bit(&rc, &m->is_rep_g2[state])) {
                            dist = rep2;
                            rep2 = rep1;
                            rep1 = rep0;
                            rep0 = dist;
                        } else {
                            dist = rep3;
                            rep3 = rep2;
                            rep2 = rep1;
                            rep1 = rep0;
                            rep0 = dist;
                        }
                    }
                }
                len = bitlz_dec_len(&rc, &m->rep_len_codec, pos_state);
                state = bitlz_state_next_rep(state);
            } else {
                len = bitlz_dec_len(&rc, &m->len_codec, pos_state);
                int len_st = len < 6 ? (int)(len - 2) : 3;
                int slot = bitlz_rc_dec_tree(&rc, m->dist_slot[len_st], 6);
                if (slot < 4) {
                    dist = (uint32_t)(slot + 1);
                } else {
                    int footer_bits = (slot >> 1) - 1;
                    uint32_t base = (2 | (slot & 1)) << footer_bits;
                    if (slot < 14) {
                        uint32_t diff = bitlz_rc_dec_rev_tree(&rc, m->dist_special[slot], footer_bits);
                        dist = base + diff + 1;
                    } else {
                        uint32_t direct = bitlz_rc_dec_direct(&rc, footer_bits - 4);
                        uint32_t align = bitlz_rc_dec_rev_tree(&rc, m->dist_align, 4);
                        dist = base + (direct << 4) + align + 1;
                    }
                }
                rep3 = rep2;
                rep2 = rep1;
                rep1 = rep0;
                rep0 = dist;
                state = bitlz_state_next_match(state);
            }

            if (pos < dist || pos + len > out_len) { free(m); return 0; }
            for (uint32_t k = 0; k < len; ++k) {
                out[pos + k] = out[pos + k - dist];
            }
            pos += len;
        }
    }
    free(m);
    return 1;
}

#ifndef LBC_TEST_LZ_SELECTION
/* =========================================================================
   Mode 10: LBC-CMix (Advanced Context Mixing with Dual-Rate Counters,
   Multi-order, Word, Stride, Indirect Models, Fixed-Point Perceptrons & APM)
   ========================================================================= */

#define LBC_CMIX_SCALE 4096
#define LBC_CMIX_K 16
#define LBC_CMIX_INPUTS (2 * LBC_CMIX_K + 1 + 2 + 1) /* 36 inputs */
#define LBC_CMIX_MIXER_INIT (((19 * 65536 / 4) / LBC_CMIX_INPUTS) * 2 / 5)
#define LBC_CMIX_LR_MUL 10
#define LBC_CMIX_SLOW_LIMIT 255

static inline int lbc_clamp_val(int v, int lo, int hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static inline int lbc_isquash(int d) {
    static const int t[33] = {
        1, 2, 3, 6, 10, 16, 27, 45, 73, 120, 194, 310, 488, 747, 1101, 1546,
        2047, 2549, 2994, 3348, 3607, 3785, 3901, 3975, 4022, 4050, 4068, 4079,
        4085, 4089, 4092, 4093, 4094
    };
    if (d > 2047) return 4095;
    if (d < -2047) return 1;
    int w = d & 127;
    int i = (d >> 7) + 16;
    return (t[i] * (128 - w) + t[i + 1] * w + 64) >> 7;
}

typedef struct {
    int16_t stretch[4096];
    int rate[1024];
} CMixMathTables;

static CMixMathTables g_cmix_tabs;
static volatile int g_cmix_tabs_inited = 0;

static void cmix_init_math_tables(void) {
    if (__atomic_load_n(&g_cmix_tabs_inited, __ATOMIC_ACQUIRE)) return;
    CMixMathTables tabs;
    int pi = 0;
    for (int x = -2047; x <= 2047; ++x) {
        int v = lbc_isquash(x);
        for (int j = pi; j <= v; ++j) tabs.stretch[j] = (int16_t)x;
        pi = v + 1;
    }
    for (int j = pi; j < 4096; ++j) tabs.stretch[j] = 2047;
    for (int n = 0; n < 1024; ++n) tabs.rate[n] = 131072 / (2 * n + 3);
    memcpy(&g_cmix_tabs, &tabs, sizeof(tabs));
    __atomic_store_n(&g_cmix_tabs_inited, 1, __ATOMIC_RELEASE);
}

static inline uint32_t cmix_hash(uint32_t a, uint32_t b, uint32_t c) {
    uint32_t h = a * 0x9E3779B1u ^ b * 0x85EBCA6Bu ^ c * 0xC2B2AE35u;
    h ^= h >> 15;
    h *= 0x2C1B3C6Du;
    h ^= h >> 12;
    return h;
}

static inline void cmix_update_slow_counter(uint32_t *e, int y, uint32_t limit, const int *rt) {
    uint32_t n = *e & 1023;
    int64_t p = *e >> 10;
    int64_t target = y ? (1 << 22) - 1 : 0;
    p += ((target - p) * rt[n]) >> 16;
    if (n < limit) ++n;
    *e = ((uint32_t)p << 10) | n;
}

/* Binary Range Coder for CMix */
typedef struct {
    uint32_t x1, x2;
    uint8_t *out;
    size_t pos, cap;
} CMixRCEnc;

static void cmix_rc_enc_init(CMixRCEnc *rc, uint8_t *out, size_t cap) {
    rc->x1 = 0; rc->x2 = 0xFFFFFFFFU; rc->out = out; rc->pos = 0; rc->cap = cap;
}

static inline void cmix_rc_enc_bit(CMixRCEnc *rc, int bit, uint32_t p16) {
    uint32_t xmid = rc->x1 + (uint32_t)(((uint64_t)(rc->x2 - rc->x1) * p16) >> 16);
    if (bit) rc->x2 = xmid; else rc->x1 = xmid + 1;
    while (((rc->x1 ^ rc->x2) & 0xFF000000U) == 0) {
        if (rc->pos < rc->cap) rc->out[rc->pos++] = (uint8_t)(rc->x2 >> 24);
        rc->x1 <<= 8;
        rc->x2 = (rc->x2 << 8) | 255;
    }
}

static void cmix_rc_enc_flush(CMixRCEnc *rc) {
    if (rc->pos < rc->cap) rc->out[rc->pos++] = (uint8_t)(rc->x1 >> 24);
}

typedef struct {
    uint32_t x1, x2, x;
    const uint8_t *in;
    size_t pos, len;
} CMixRCDec;

static inline uint8_t cmix_rc_dec_byte(CMixRCDec *rc) {
    return rc->pos < rc->len ? rc->in[rc->pos++] : 0xFF;
}

static void cmix_rc_dec_init(CMixRCDec *rc, const uint8_t *in, size_t len) {
    rc->x1 = 0; rc->x2 = 0xFFFFFFFFU; rc->x = 0; rc->in = in; rc->pos = 0; rc->len = len;
    for (int i = 0; i < 4; ++i) rc->x = (rc->x << 8) | cmix_rc_dec_byte(rc);
}

static inline int cmix_rc_dec_bit(CMixRCDec *rc, uint32_t p16) {
    uint32_t xmid = rc->x1 + (uint32_t)(((uint64_t)(rc->x2 - rc->x1) * p16) >> 16);
    int bit = (rc->x <= xmid);
    if (bit) rc->x2 = xmid; else rc->x1 = xmid + 1;
    while (((rc->x1 ^ rc->x2) & 0xFF000000U) == 0) {
        rc->x1 <<= 8;
        rc->x2 = (rc->x2 << 8) | 255;
        rc->x = (rc->x << 8) | cmix_rc_dec_byte(rc);
    }
    return bit;
}

/* Linear Perceptron Mixer */
typedef struct {
    int n;
    int sets;
    int32_t *w;
} CMixMixer;

static int cmix_mixer_init(CMixMixer *m, int n, int sets, int w_init) {
    m->n = n;
    m->sets = sets;
    m->w = malloc((size_t)n * (size_t)sets * sizeof(int32_t));
    if (!m->w) return 0;
    for (size_t i = 0; i < (size_t)n * (size_t)sets; ++i) m->w[i] = w_init;
    return 1;
}

static void cmix_mixer_free(CMixMixer *m) {
    if (m->w) { free(m->w); m->w = NULL; }
}

static inline int cmix_mixer_dot(const CMixMixer *m, const int *x, int set) {
    const int32_t *ww = &m->w[(size_t)set * LBC_CMIX_INPUTS];
    int32_t s0 = 0, s1 = 0;
    for (int i = 0; i < 36; i += 4) {
        s0 += (x[i] * ww[i]) >> 8;
        s1 += (x[i + 1] * ww[i + 1]) >> 8;
        s0 += (x[i + 2] * ww[i + 2]) >> 8;
        s1 += (x[i + 3] * ww[i + 3]) >> 8;
    }
    return lbc_clamp_val((s0 + s1) >> 8, -2047, 2047);
}

static inline void cmix_mixer_train(CMixMixer *m, const int *x, int set, int err) {
    int32_t *ww = &m->w[(size_t)set * LBC_CMIX_INPUTS];
    for (int i = 0; i < 36; i += 4) {
        int32_t d0 = (x[i] * err + (1 << 13)) >> 14;
        ww[i] = lbc_clamp_val(ww[i] + d0, -(1 << 19), (1 << 19) - 1);
        int32_t d1 = (x[i + 1] * err + (1 << 13)) >> 14;
        ww[i + 1] = lbc_clamp_val(ww[i + 1] + d1, -(1 << 19), (1 << 19) - 1);
        int32_t d2 = (x[i + 2] * err + (1 << 13)) >> 14;
        ww[i + 2] = lbc_clamp_val(ww[i + 2] + d2, -(1 << 19), (1 << 19) - 1);
        int32_t d3 = (x[i + 3] * err + (1 << 13)) >> 14;
        ww[i + 3] = lbc_clamp_val(ww[i + 3] + d3, -(1 << 19), (1 << 19) - 1);
    }
}

/* Adaptive Probability Map (APM) */
typedef struct {
    size_t n_sets;
    uint16_t *t;
    size_t last_idx;
} CMixAPM;

static int cmix_apm_init(CMixAPM *a, size_t n_sets) {
    a->n_sets = n_sets;
    a->t = malloc(n_sets * 33 * sizeof(uint16_t));
    if (!a->t) return 0;
    for (size_t i = 0; i < n_sets; ++i) {
        for (int j = 0; j < 33; ++j) {
            a->t[i * 33 + j] = (uint16_t)(lbc_isquash((j - 16) * 128) * 16);
        }
    }
    a->last_idx = 0;
    return 1;
}

static void cmix_apm_free(CMixAPM *a) {
    if (a->t) { free(a->t); a->t = NULL; }
}

static inline int cmix_apm_predict(CMixAPM *a, int pr, size_t cx, const int16_t *st) {
    int s = st[pr] + 2048;
    int lo = s >> 7, w = s & 127;
    size_t b = cx * 33 + (size_t)lo;
    a->last_idx = b + (size_t)(w >> 6);
    return (a->t[b] * (128 - w) + a->t[b + 1] * w) >> 11;
}

static inline void cmix_apm_update(CMixAPM *a, int y) {
    int g = (y << 16) + (y << 7) - y - y;
    a->t[a->last_idx] = (uint16_t)(a->t[a->last_idx] + ((g - (int)a->t[a->last_idx]) >> 7));
}

/* Context Table Slot */
typedef struct {
    uint32_t s; /* slow counter: 22-bit prob + 10-bit count */
    uint16_t f; /* fast counter: 16-bit prob */
    uint16_t x; /* 16-bit checksum tag */
} CMixSlot;

typedef struct {
    int tbits;
    int stride;
    int mbits;
    int ibits;
    CMixSlot *t[LBC_CMIX_K];
    size_t bucket[LBC_CMIX_K];
    size_t idx[LBC_CMIX_K];
    uint32_t o0[256];
    uint32_t msm[64];
    int msm_idx;
    uint32_t h[LBC_CMIX_K];
    int x[LBC_CMIX_INPUTS];
    uint32_t c0, c4, c8, wh, pw;
    uint32_t col;
    uint8_t *it;
    uint32_t ih, itv;
    int bits;
    int order_hits;
    int32_t *mm;
    size_t mptr;
    uint32_t mlen;
    CMixMixer m1, m2;
    int set1, set2, d1, d2;
    CMixAPM a1, a2, a3;
    int pr;
    uint8_t *hist;
    size_t hist_len, hist_cap;
} CMixPredictor;

static void cmix_predictor_compute_contexts(CMixPredictor *p) {
    uint32_t c1 = p->c4 & 0xFF;
    size_t pos = p->hist_len;
    p->h[0] = cmix_hash(1, p->c4 & 0xFF, 0);
    p->h[1] = cmix_hash(2, p->c4 & 0xFFFF, 0);
    p->h[2] = cmix_hash(3, p->c4 & 0xFFFFFF, 0);
    p->h[3] = cmix_hash(4, p->c4, 0);
    p->h[4] = cmix_hash(5, p->c4, p->c8 & 0xFFFF);
    p->h[5] = cmix_hash(6, p->wh, p->pw);
    p->h[6] = cmix_hash(7, (p->c4 >> 8) & 0xFFFF, 0);

    size_t k = (size_t)p->stride;
    uint32_t above = pos >= k ? p->hist[pos - k] : 0;
    uint32_t above2 = pos >= 2 * k ? p->hist[pos - 2 * k] : 0;
    p->h[7] = cmix_hash(8 + ((uint32_t)p->stride << 8), above | (above2 << 8), c1);
    p->h[8] = cmix_hash(9, p->c4 & 0xFFFF00FFu, 0);
    p->h[9] = cmix_hash(10, p->c4, p->c8 & 0xFF);
    p->h[10] = cmix_hash(11, p->itv, p->c4 & 0xFF);
    p->h[11] = cmix_hash(12, p->c4, p->c8 & 0xFFFFFF);
    p->h[12] = cmix_hash(13, p->pw, c1);
    p->h[13] = cmix_hash(14, p->col < 64 ? p->col : 64, (p->c4 & 0xFFFF));
    p->h[14] = cmix_hash(15, p->c4, p->c8);
    p->h[15] = cmix_hash(16, (p->c4 >> 16) & 0xFFFF, 0);
}

static void cmix_predictor_select_buckets(CMixPredictor *p) {
    int hits = 0;
    for (int k = 0; k < LBC_CMIX_K; ++k) {
        uint32_t h = cmix_hash(p->h[k], p->c0, 0x7F4A7C15u);
        size_t b = ((size_t)(h >> (36 - p->tbits))) << 4;
        uint16_t chk = (uint16_t)(h & 0xFFFF);
        CMixSlot *T = p->t[k];
        CMixSlot *A = T + b;
        CMixSlot *B = T + (b ^ 16);
        CMixSlot *use;
        int found = 1;
        if (A->x == chk) use = A;
        else if (B->x == chk) use = B;
        else {
            found = 0;
            use = A->f <= B->f ? A : B;
            memset(use + 1, 0, 15 * sizeof(CMixSlot));
            use->x = chk;
            use->f = 0;
        }
        if (found && k < 5) ++hits;
        if (use->f < 65535) ++use->f;
        p->bucket[k] = (size_t)(use - T);
    }
    p->order_hits = hits;
}

static void cmix_predictor_predict(CMixPredictor *p) {
    uint32_t nib = p->bits < 4 ? p->c0 : ((1u << (p->bits - 4)) | (p->c0 & ((1u << (p->bits - 4)) - 1)));
    const int16_t *st = g_cmix_tabs.stretch;

    for (int k = 0; k < LBC_CMIX_K; ++k) {
        size_t i = p->bucket[k] + nib;
        p->idx[k] = i;
        const CMixSlot *sl = &p->t[k][i];
        p->x[2 * k] = st[(sl->s ^ 0x80000000u) >> 20];
        p->x[2 * k + 1] = st[(sl->f ^ 0x8000u) >> 4];
    }

    p->x[2 * LBC_CMIX_K] = st[p->o0[p->c0] >> 20];

    int mb = 0;
    p->msm_idx = -1;
    p->x[2 * LBC_CMIX_K + 1] = 0;
    p->x[2 * LBC_CMIX_K + 2] = 0;

    if (p->mlen > 0) {
        uint32_t pb = p->hist[p->mptr];
        if (((pb + 256) >> (8 - p->bits)) == p->c0) {
            int expect = (pb >> (7 - p->bits)) & 1;
            uint32_t b = p->mlen < 16 ? p->mlen : 16 + ((p->mlen - 16) >> 3 < 15 ? (p->mlen - 16) >> 3 : 15);
            p->msm_idx = (int)(b * 2 + (uint32_t)expect);
            p->x[2 * LBC_CMIX_K + 1] = st[p->msm[p->msm_idx] >> 20];
            int s = (int)(p->mlen < 31 ? p->mlen : 31) * 64;
            p->x[2 * LBC_CMIX_K + 2] = expect ? s : -s;
            mb = p->mlen < 16 ? 1 : (p->mlen < 32 ? 2 : 3);
        }
    }

    p->x[2 * LBC_CMIX_K + 3] = 256;
    p->set1 = (int)p->c0 | (p->order_hits << 8);
    p->set2 = (mb << 8) | (int)(p->c4 & 0xFF);

    p->d1 = cmix_mixer_dot(&p->m1, p->x, p->set1);
    p->d2 = cmix_mixer_dot(&p->m2, p->x, p->set2);
    int pm = lbc_isquash((p->d1 + p->d2) >> 1);
    int p1 = cmix_apm_predict(&p->a1, pm, p->c0, st);
    int p2 = cmix_apm_predict(&p->a2, pm, (size_t)(p->c0 | ((p->c4 & 0xFF) << 8)), st);
    int p3 = cmix_apm_predict(&p->a3, pm, (size_t)(p->c0 | (((p->c4 >> 8) & 0xFF) << 8)), st);
    int combined = (pm + p1 + 2 * p2 + 2 * p3 + 3) / 6;
    p->pr = lbc_clamp_val(combined, 1, 4095);
}

static void cmix_predictor_byte_done(CMixPredictor *p) {
    uint8_t c = (uint8_t)(p->c0 & 255);
    if (p->hist_len >= p->hist_cap) {
        size_t new_cap = p->hist_cap ? p->hist_cap * 2 : 1024;
        uint8_t *new_hist = realloc(p->hist, new_cap);
        if (!new_hist) fail("out of memory expanding history");
        p->hist = new_hist;
        p->hist_cap = new_cap;
    }
    p->hist[p->hist_len++] = c;
    size_t pos = p->hist_len;

    p->it[p->ih] = c;
    p->c8 = (p->c8 << 8) | (p->c4 >> 24);
    p->c4 = (p->c4 << 8) | c;
    p->ih = cmix_hash(2, p->c4 & 0xFFFF, 0x9E3779B1u) >> (32 - p->ibits);
    p->itv = p->it[p->ih];
    p->c0 = 1;
    p->bits = 0;

    if (c == '\n') p->col = 0;
    else if (p->col < 1000) p->col++;

    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80) {
        p->wh = (p->wh ^ (uint32_t)(c | 0x20)) * 0x01000193u + 1;
    } else if (p->wh) {
        p->pw = p->wh;
        p->wh = 0;
    }

    if (p->mlen > 0) {
        if (p->hist[p->mptr] == c) {
            if (p->mlen < 65535) ++p->mlen;
            ++p->mptr;
        } else {
            p->mlen = 0;
        }
    }

    if (pos >= 6) {
        uint32_t h = cmix_hash(p->c4, p->c8 & 0xFFFF, 0x51) >> (32 - p->mbits);
        if (p->mlen == 0) {
            uint32_t cand = (uint32_t)p->mm[h];
            if (cand > 0) {
                uint32_t l = 0;
                while (l < 64 && l < cand && p->hist[cand - 1 - l] == p->hist[pos - 1 - l]) ++l;
                if (l >= 6) { p->mlen = l; p->mptr = cand; }
            }
        }
        p->mm[h] = (int32_t)pos;
    }

    cmix_predictor_compute_contexts(p);
    cmix_predictor_select_buckets(p);
}

static void cmix_predictor_update(CMixPredictor *p, int y) {
    const int *rt = g_cmix_tabs.rate;
    for (int k = 0; k < LBC_CMIX_K; ++k) {
        CMixSlot *sl = &p->t[k][p->idx[k]];
        uint32_t sv = sl->s ^ 0x80000000u;
        cmix_update_slow_counter(&sv, y, LBC_CMIX_SLOW_LIMIT, rt);
        sl->s = sv ^ 0x80000000u;
        uint32_t f = sl->f ^ 0x8000u;
        f = y ? f + ((65536 - f) >> 2) : f - (f >> 2);
        sl->f = (uint16_t)(f ^ 0x8000u);
    }

    cmix_update_slow_counter(&p->o0[p->c0], y, 1023, rt);
    if (p->msm_idx >= 0) cmix_update_slow_counter(&p->msm[p->msm_idx], y, 1023, rt);

    cmix_mixer_train(&p->m1, p->x, p->set1, ((y << 12) - lbc_isquash(p->d1)) * LBC_CMIX_LR_MUL);
    cmix_mixer_train(&p->m2, p->x, p->set2, ((y << 12) - lbc_isquash(p->d2)) * LBC_CMIX_LR_MUL);
    cmix_apm_update(&p->a1, y);
    cmix_apm_update(&p->a2, y);
    cmix_apm_update(&p->a3, y);

    p->c0 = (p->c0 << 1) | (uint32_t)y;
    if (++p->bits == 8) cmix_predictor_byte_done(p);
    else if (p->bits == 4) cmix_predictor_select_buckets(p);

    cmix_predictor_predict(p);
}

static CMixPredictor *cmix_predictor_create(int tbits, int stride, size_t reserve) {
    cmix_init_math_tables();
    CMixPredictor *p = calloc(1, sizeof(CMixPredictor));
    if (!p) return NULL;
    p->tbits = tbits;
    p->stride = stride > 0 ? stride : 4;
    p->mbits = tbits < 22 ? tbits : 22;
    p->ibits = tbits < 22 ? tbits : 22;
    p->c0 = 1;

    size_t sz = (size_t)1 << tbits;
    for (int k = 0; k < LBC_CMIX_K; ++k) {
        p->t[k] = calloc(sz, sizeof(CMixSlot));
        if (!p->t[k]) {
            for (int j = 0; j < k; ++j) free(p->t[j]);
            free(p);
            return NULL;
        }
    }
    for (int i = 0; i < 256; ++i) p->o0[i] = 1u << 31;
    for (int i = 0; i < 64; ++i) p->msm[i] = 1u << 31;

    p->mm = calloc((size_t)1 << p->mbits, sizeof(int32_t));
    p->it = calloc((size_t)1 << p->ibits, sizeof(uint8_t));
    p->ih = cmix_hash(2, 0, 0x9E3779B1u) >> (32 - p->ibits);

    p->hist_cap = reserve > 1024 ? reserve : 1024;
    p->hist = malloc(p->hist_cap);

    if (!p->mm || !p->it || !p->hist ||
        !cmix_mixer_init(&p->m1, LBC_CMIX_INPUTS, 256 * 6, LBC_CMIX_MIXER_INIT) ||
        !cmix_mixer_init(&p->m2, LBC_CMIX_INPUTS, 1024, LBC_CMIX_MIXER_INIT) ||
        !cmix_apm_init(&p->a1, 256) ||
        !cmix_apm_init(&p->a2, 65536) ||
        !cmix_apm_init(&p->a3, 65536)) {
        for (int k = 0; k < LBC_CMIX_K; ++k) free(p->t[k]);
        if (p->mm) free(p->mm);
        if (p->it) free(p->it);
        if (p->hist) free(p->hist);
        cmix_mixer_free(&p->m1);
        cmix_mixer_free(&p->m2);
        cmix_apm_free(&p->a1);
        cmix_apm_free(&p->a2);
        cmix_apm_free(&p->a3);
        free(p);
        return NULL;
    }

    cmix_predictor_compute_contexts(p);
    cmix_predictor_select_buckets(p);
    cmix_predictor_predict(p);
    return p;
}

static void cmix_predictor_free(CMixPredictor *p) {
    if (!p) return;
    for (int k = 0; k < LBC_CMIX_K; ++k) if (p->t[k]) free(p->t[k]);
    if (p->mm) free(p->mm);
    if (p->it) free(p->it);
    if (p->hist) free(p->hist);
    cmix_mixer_free(&p->m1);
    cmix_mixer_free(&p->m2);
    cmix_apm_free(&p->a1);
    cmix_apm_free(&p->a2);
    cmix_apm_free(&p->a3);
    free(p);
}

static int lbc_detect_stride(const uint8_t *x, size_t m) {
    if (m < 256) return 4;
    size_t sample_size = m > 32768 ? 32768 : m;
    int best_stride = 4;
    uint64_t best_score = 0;
    for (int k = 2; k <= 64; ++k) {
        size_t eq = 0;
        for (size_t i = (size_t)k; i < sample_size; ++i) {
            if (x[i] == x[i - k]) ++eq;
        }
        uint64_t sc = ((uint64_t)eq * 1000000ULL) / (sample_size - (size_t)k);
        if (sc > (best_score * 102ULL) / 100ULL) {
            best_score = sc;
            best_stride = k;
        }
    }
    return best_stride;
}

static uint8_t *encode_cmix(const uint8_t *data, size_t n, int tbits, int stride, size_t *out_len) {
    size_t out_cap = n + 65536;
    uint8_t *out = malloc(out_cap);
    if (!out) return NULL;

    CMixRCEnc rc;
    cmix_rc_enc_init(&rc, out, out_cap);

    CMixPredictor *p = cmix_predictor_create(tbits, stride, n);
    if (!p) { free(out); return NULL; }

    for (size_t i = 0; i < n; ++i) {
        int byte = data[i];
        for (int b = 7; b >= 0; --b) {
            int y = (byte >> b) & 1;
            uint32_t p16 = (uint32_t)p->pr << 4;
            cmix_rc_enc_bit(&rc, y, p16);
            cmix_predictor_update(p, y);
        }
    }

    cmix_rc_enc_flush(&rc);
    cmix_predictor_free(p);
    *out_len = rc.pos;
    return out;
}

static int decode_cmix(const uint8_t *src, size_t src_len, uint8_t *out, size_t n, int tbits, int stride) {
    CMixRCDec rc;
    cmix_rc_dec_init(&rc, src, src_len);

    CMixPredictor *p = cmix_predictor_create(tbits, stride, n);
    if (!p) return 0;

    for (size_t i = 0; i < n; ++i) {
        int byte = 0;
        for (int b = 7; b >= 0; --b) {
            uint32_t p16 = (uint32_t)p->pr << 4;
            int y = cmix_rc_dec_bit(&rc, p16);
            cmix_predictor_update(p, y);
            byte = (byte << 1) | y;
        }
        out[i] = (uint8_t)byte;
    }

    cmix_predictor_free(p);
    return 1;
}


#endif /* LBC_TEST_LZ_SELECTION */

static void write_chunk_record(FILE *spool, const uint8_t *data, uint32_t length) {
    uint64_t frequencies[256] = {0};
    for (uint32_t i = 0; i < length; ++i) ++frequencies[data[i]];
    uint64_t bit_count = 0;
    size_t payload_length = 0;
    uint8_t *packed = encode_huffman(data, length, frequencies, HUFFMAN_HEADER_BYTES,
                                     &bit_count, &payload_length);
    uint64_t plain_size = packed == NULL ? 21U + length :
        21U + HUFFMAN_HEADER_BYTES + payload_length;

    size_t token_length = 0;
    uint8_t *tokens = encode_lz_tokens(data, length, 32768U, &token_length);
    uint64_t token_frequencies[256] = {0};
    for (size_t i = 0; i < token_length; ++i) ++token_frequencies[tokens[i]];
    uint64_t token_bits = 0;
    size_t token_payload_length = 0;
    uint8_t *packed_tokens = encode_huffman(tokens, token_length, token_frequencies, 0,
                                             &token_bits, &token_payload_length);
    uint64_t token_symbols = 0;
    for (unsigned symbol = 0; symbol < 256; ++symbol)
        if (token_frequencies[symbol] != 0) ++token_symbols;
    uint64_t sparse_table_bytes = 2U;
    for (unsigned symbol = 0; symbol < 256; ++symbol)
        if (token_frequencies[symbol] != 0)
            sparse_table_bytes += 1U + varint_size((uint32_t)token_frequencies[symbol]);
    uint64_t lz_raw_size = tokens == NULL ? UINT64_MAX : 21U + token_length;
    uint64_t lz_huffman_size =
        packed_tokens != NULL && token_length > HUFFMAN_HEADER_BYTES &&
        token_payload_length < token_length - HUFFMAN_HEADER_BYTES ?
        21U + HUFFMAN_HEADER_BYTES + token_payload_length : UINT64_MAX;
    uint64_t lz_sparse_size =
        packed_tokens != NULL && sparse_table_bytes < token_length &&
        token_payload_length < token_length - sparse_table_bytes ?
        21U + sparse_table_bytes + token_payload_length : UINT64_MAX;

    /* Wider searches can make greedy token coding worse. Compare complete
       record sizes and retain the original short-window candidate on ties. */
    if (opt_level >= 4 && length > 32768U && length <= MAX_LZ_CHUNK) {
        uint32_t extra_windows[3];
        size_t num_extra = 0;
        extra_windows[num_extra++] = 1048576U;
        if (length > 1048576U) {
            extra_windows[num_extra++] = 2097152U;
            if (length > 2097152U) extra_windows[num_extra++] = 4194304U;
        }
        uint64_t current_best = lz_raw_size < lz_huffman_size ? lz_raw_size : lz_huffman_size;
        if (lz_sparse_size < current_best) current_best = lz_sparse_size;

        for (size_t w = 0; w < num_extra; ++w) {
            uint32_t win = extra_windows[w];
            size_t wide_length = 0, wide_payload_length = 0;
            uint8_t *wide_tokens = encode_lz_tokens(data, length, win, &wide_length);
            if (!wide_tokens) continue;
            uint64_t wide_frequencies[256] = {0};
            for (size_t i = 0; i < wide_length; ++i) ++wide_frequencies[wide_tokens[i]];
            uint64_t wide_bits = 0, wide_symbols = 0, wide_table_bytes = 2U;
            for (unsigned symbol = 0; symbol < 256; ++symbol) {
                if (wide_frequencies[symbol] == 0) continue;
                ++wide_symbols;
                wide_table_bytes += 1U + varint_size((uint32_t)wide_frequencies[symbol]);
            }
            uint8_t *wide_packed = encode_huffman(wide_tokens, wide_length, wide_frequencies,
                                                  0, &wide_bits, &wide_payload_length);
            uint64_t wide_raw_size = 21U + wide_length;
            uint64_t wide_full_size = wide_packed != NULL && wide_length > HUFFMAN_HEADER_BYTES &&
                wide_payload_length < wide_length - HUFFMAN_HEADER_BYTES ?
                21U + HUFFMAN_HEADER_BYTES + wide_payload_length : UINT64_MAX;
            uint64_t wide_sparse_size = wide_packed != NULL && wide_table_bytes < wide_length &&
                wide_payload_length < wide_length - wide_table_bytes ?
                21U + wide_table_bytes + wide_payload_length : UINT64_MAX;
            uint64_t wide_best = wide_raw_size < wide_full_size ? wide_raw_size : wide_full_size;
            if (wide_sparse_size < wide_best) wide_best = wide_sparse_size;
            if (wide_best < current_best) {
                free(tokens);
                free(packed_tokens);
                tokens = wide_tokens;
                packed_tokens = wide_packed;
                token_length = wide_length;
                token_payload_length = wide_payload_length;
                token_bits = wide_bits;
                token_symbols = wide_symbols;
                sparse_table_bytes = wide_table_bytes;
                memcpy(token_frequencies, wide_frequencies, sizeof(token_frequencies));
                lz_raw_size = wide_raw_size;
                lz_huffman_size = wide_full_size;
                lz_sparse_size = wide_sparse_size;
                current_best = wide_best;
            } else {
                free(wide_tokens);
                free(wide_packed);
            }
        }
    }

    uint32_t bwt_primary = 0;
    size_t bwt_token_length = 0, bwt_payload_length = 0;
    uint8_t *bwt_tokens = NULL;
    uint64_t bwt_frequencies[256] = {0};
    uint64_t bwt_bits = 0, bwt_symbols = 0;
    uint64_t bwt_table_bytes = 6U;
    uint8_t *packed_bwt = NULL;
    if (opt_level >= 4) {
        uint8_t *bwt_last = bwt_transform(data, length, &bwt_primary);
        bwt_tokens = bwt_last == NULL ? NULL :
            encode_bwt_mtf(bwt_last, length, &bwt_token_length);
        free(bwt_last);
        if (bwt_tokens != NULL) {
            for (size_t i = 0; i < bwt_token_length; ++i) ++bwt_frequencies[bwt_tokens[i]];
            for (unsigned symbol = 0; symbol < 256; ++symbol)
                if (bwt_frequencies[symbol] != 0) ++bwt_symbols;
            for (unsigned symbol = 0; symbol < 256; ++symbol)
                if (bwt_frequencies[symbol] != 0)
                    bwt_table_bytes += 1U + varint_size((uint32_t)bwt_frequencies[symbol]);
            packed_bwt = encode_huffman(bwt_tokens, bwt_token_length, bwt_frequencies, bwt_table_bytes,
                                        &bwt_bits, &bwt_payload_length);
        }
    }
    uint64_t bwt_size = packed_bwt == NULL ? UINT64_MAX :
        21U + bwt_table_bytes + bwt_payload_length;

    /* Evaluate Range Coder candidate with adaptive statistical models */
    size_t rc_payload_length = 0;
    uint64_t rc_model_type = 0;
    uint8_t *rc_packed = NULL;
    if (opt_level >= 4 && length <= MAX_LZ_CHUNK) {
        size_t rc0_len = 0;
        uint8_t *rc0_data = encode_range_order0(data, length, &rc0_len);
        size_t rc1_len = 0;
        uint8_t *rc1_data = encode_range_order1(data, length, &rc1_len);
        if (rc0_data != NULL && (rc1_data == NULL || rc0_len <= rc1_len)) {
            rc_packed = rc0_data;
            rc_payload_length = rc0_len;
            rc_model_type = 0;
            free(rc1_data);
        } else if (rc1_data != NULL) {
            rc_packed = rc1_data;
            rc_payload_length = rc1_len;
            rc_model_type = 1;
            free(rc0_data);
        }
    }
    uint64_t rc_size = rc_packed == NULL ? UINT64_MAX : 21U + rc_payload_length;

    /* Evaluate Mode 9: LBC-BitLZ (Advanced LZ-Range Coder with Repeat Distances) */
    size_t bitlz_payload_length = 0;
    uint8_t *bitlz_packed = NULL;
    uint64_t bitlz_flags = 0;
#ifndef LBC_TEST_LZ_SELECTION
    if (current_chunk_setting != 65536 && length <= MAX_LZ_CHUNK) {
        size_t b_len = 0;
        uint8_t *b_data = encode_bit_lz(data, length, &b_len);
        if (b_data != NULL) {
            bitlz_packed = b_data;
            bitlz_payload_length = b_len;
            bitlz_flags = 0;
        }
        if (length >= 512 && lbc_has_x86_calls(data, length)) {
            uint8_t *bcj_buf = malloc(length);
            if (bcj_buf != NULL) {
                memcpy(bcj_buf, data, length);
                lbc_bcj_x86_filter(bcj_buf, length, 1);
                size_t bcj_len = 0;
                uint8_t *bcj_data = encode_bit_lz(bcj_buf, length, &bcj_len);
                free(bcj_buf);
                if (bcj_data != NULL) {
                    if (bitlz_packed == NULL || bcj_len < bitlz_payload_length) {
                        free(bitlz_packed);
                        bitlz_packed = bcj_data;
                        bitlz_payload_length = bcj_len;
                        bitlz_flags = 1;
                    } else {
                        free(bcj_data);
                    }
                }
            }
        }
    }
#endif
    uint64_t bitlz_size = bitlz_packed == NULL ? UINT64_MAX : 21U + bitlz_payload_length;
    /* Evaluate Mode 10: LBC-CMix (Maximum Ratio Context Mixing) */
    size_t cmix_payload_length = 0;
    uint8_t *cmix_packed = NULL;
    uint64_t cmix_flags = 0;
#ifndef LBC_TEST_LZ_SELECTION
    if (opt_level >= 7 && current_chunk_setting != 65536 && length <= MAX_LZ_CHUNK) {
        int stride = lbc_detect_stride(data, length);
        int tbits;
        if (length <= 32768) tbits = 18;
        else if (length <= 131072) tbits = 19;
        else if (length <= 524288) tbits = 20;
        else if (length <= 2097152) tbits = 21;
        else tbits = opt_level >= 9 ? 23 : 22;
        size_t c_len = 0;
        uint8_t *c_data = encode_cmix(data, length, tbits, stride, &c_len);
        if (c_data != NULL) {
            cmix_packed = c_data;
            cmix_payload_length = c_len;
            cmix_flags = ((uint64_t)stride << 8) | ((uint64_t)tbits << 16);
        }
        if (length >= 512 && lbc_has_x86_calls(data, length)) {
            uint8_t *bcj_buf = malloc(length);
            if (bcj_buf != NULL) {
                memcpy(bcj_buf, data, length);
                lbc_bcj_x86_filter(bcj_buf, length, 1);
                int bcj_stride = lbc_detect_stride(bcj_buf, length);
                size_t bcj_len = 0;
                uint8_t *bcj_data = encode_cmix(bcj_buf, length, tbits, bcj_stride, &bcj_len);
                free(bcj_buf);
                if (bcj_data != NULL) {
                    if (cmix_packed == NULL || bcj_len < cmix_payload_length) {
                        free(cmix_packed);
                        cmix_packed = bcj_data;
                        cmix_payload_length = bcj_len;
                        cmix_flags = 1 | ((uint64_t)bcj_stride << 8) | ((uint64_t)tbits << 16);
                    } else {
                        free(bcj_data);
                    }
                }
            }
        }
    }
#endif
    uint64_t cmix_size = cmix_packed == NULL ? UINT64_MAX : 21U + cmix_payload_length;

    if (cmix_size < plain_size && cmix_size < bitlz_size &&
        cmix_size < rc_size && cmix_size < lz_raw_size &&
        cmix_size < lz_huffman_size && cmix_size < lz_sparse_size &&
        cmix_size < bwt_size) {
        put_u32(spool, length);
        put_u8(spool, 10);
        put_u64(spool, cmix_flags);
        put_u64(spool, cmix_payload_length);
        write_exact(spool, cmix_packed, cmix_payload_length);
    } else if (bitlz_size < plain_size && bitlz_size < rc_size &&
        bitlz_size < lz_raw_size && bitlz_size < lz_huffman_size &&
        bitlz_size < lz_sparse_size && bitlz_size < bwt_size) {
        put_u32(spool, length);
        put_u8(spool, 9);
        put_u64(spool, bitlz_flags);
        put_u64(spool, bitlz_payload_length);
        write_exact(spool, bitlz_packed, bitlz_payload_length);
    } else if (rc_size < plain_size && rc_size < lz_raw_size &&
        rc_size < lz_huffman_size && rc_size < lz_sparse_size &&
        rc_size < bwt_size) {
        put_u32(spool, length);
        put_u8(spool, 8);
        put_u64(spool, rc_model_type);
        put_u64(spool, rc_payload_length);
        write_exact(spool, rc_packed, rc_payload_length);
    } else if (bwt_size < plain_size && bwt_size < lz_raw_size &&
        bwt_size < lz_huffman_size && bwt_size < lz_sparse_size) {
        put_u32(spool, length);
        put_u8(spool, 7);
        put_u64(spool, bwt_bits);
        put_u64(spool, bwt_payload_length);
        put_u32(spool, bwt_primary);
        put_u8(spool, (uint8_t)(bwt_symbols >> 8));
        put_u8(spool, (uint8_t)bwt_symbols);
        for (unsigned symbol = 0; symbol < 256; ++symbol) {
            if (bwt_frequencies[symbol] == 0) continue;
            if (bwt_frequencies[symbol] > UINT32_MAX)
                fail("BWT frequency exceeds sparse table range");
            put_u8(spool, (uint8_t)symbol);
            put_varint(spool, (uint32_t)bwt_frequencies[symbol]);
        }
        write_exact(spool, packed_bwt, bwt_payload_length);
    } else if (lz_sparse_size < plain_size && lz_sparse_size < lz_raw_size &&
               lz_sparse_size < lz_huffman_size) {
        put_u32(spool, length);
        put_u8(spool, 6);
        put_u64(spool, token_bits);
        put_u64(spool, token_payload_length);
        put_u8(spool, (uint8_t)(token_symbols >> 8));
        put_u8(spool, (uint8_t)token_symbols);
        for (unsigned symbol = 0; symbol < 256; ++symbol) {
            if (token_frequencies[symbol] == 0) continue;
            if (token_frequencies[symbol] > UINT32_MAX)
                fail("LZ frequency exceeds sparse table range");
            put_u8(spool, (uint8_t)symbol);
            put_varint(spool, (uint32_t)token_frequencies[symbol]);
        }
        write_exact(spool, packed_tokens, token_payload_length);
    } else if (lz_huffman_size < plain_size && lz_huffman_size < lz_raw_size) {
        put_u32(spool, length);
        put_u8(spool, 2);
        put_u64(spool, token_bits);
        put_u64(spool, token_payload_length);
        for (unsigned i = 0; i < 256; ++i) put_u64(spool, token_frequencies[i]);
        write_exact(spool, packed_tokens, token_payload_length);
    } else if (lz_raw_size < plain_size) {
        put_u32(spool, length);
        put_u8(spool, 3);
        put_u64(spool, token_length);
        put_u64(spool, token_length);
        write_exact(spool, tokens, token_length);
    } else if (packed == NULL) {
        put_u32(spool, length);
        put_u8(spool, 0);
        put_u64(spool, 0);
        put_u64(spool, length);
        write_exact(spool, data, length);
    } else {
        put_u32(spool, length);
        put_u8(spool, 1);
        put_u64(spool, bit_count);
        put_u64(spool, payload_length);
        for (unsigned i = 0; i < 256; ++i) put_u64(spool, frequencies[i]);
        write_exact(spool, packed, payload_length);
    }
    free(packed);
    free(tokens);
    free(packed_tokens);
    free(bwt_tokens);
    free(packed_bwt);
    free(rc_packed);
    free(bitlz_packed);
    free(cmix_packed);
}

static void compress_file(const char *input_path, const char *output_path, uint32_t chunk_size) {
    current_chunk_setting = chunk_size;
    verify_new_output(output_path);
    size_t source_size;
    uint8_t *source = load_file(input_path, &source_size);
    uint64_t blocks64 = source_size == 0 ? 0 : (source_size + chunk_size - 1U) / chunk_size;
    if (blocks64 > MAX_BLOCKS) fail("too many blocks; increase chunk size (maximum 1,000,000)");
    uint32_t block_count = (uint32_t)blocks64;
    size_t slot_count = next_power_of_two((size_t)(block_count == 0 ? 1 : (uint64_t)block_count * 2U));
    HashSlot *slots = calloc(slot_count, sizeof(*slots));
    uint32_t *block_ids = calloc(block_count == 0 ? 1 : block_count, sizeof(*block_ids));
    UniqueBlock *unique = calloc(block_count == 0 ? 1 : block_count, sizeof(*unique));
    Run *runs = calloc(block_count == 0 ? 1 : block_count, sizeof(*runs));
    if (slots == NULL || block_ids == NULL || unique == NULL || runs == NULL)
        fail("out of memory building block index");

    uint32_t unique_count = 0;
    size_t mask = slot_count - 1U;
    for (uint32_t block = 0; block < block_count; ++block) {
        size_t offset = (size_t)block * chunk_size;
        size_t length = source_size - offset;
        if (length > chunk_size) length = chunk_size;
        uint64_t hash = fnv1a64(source + offset, length);
        size_t slot = (size_t)hash & mask;
        uint32_t found = UINT32_MAX;
        while (slots[slot].used) {
            uint32_t id = slots[slot].id;
            if (slots[slot].hash == hash && unique[id].length == length &&
                memcmp(source + unique[id].offset, source + offset, length) == 0) {
                found = id;
                break;
            }
            slot = (slot + 1U) & mask;
        }
        if (found == UINT32_MAX) {
            found = unique_count++;
            unique[found].offset = offset;
            unique[found].length = (uint32_t)length;
            slots[slot].used = 1;
            slots[slot].hash = hash;
            slots[slot].id = found;
        }
        block_ids[block] = found;
    }
    uint32_t run_count = 0;
    for (uint32_t block = 0; block < block_count; ++block) {
        uint32_t id = block_ids[block];
        if (run_count != 0 && runs[run_count - 1U].id == id && runs[run_count - 1U].count != UINT32_MAX)
            ++runs[run_count - 1U].count;
        else {
            runs[run_count].id = id;
            runs[run_count].count = 1;
            ++run_count;
        }
    }

    char *spool_path = NULL;
    FILE *spool = create_temp(output_path, "spool", &spool_path);
    for (uint32_t id = 0; id < unique_count; ++id)
        write_chunk_record(spool, source + unique[id].offset, unique[id].length);
    if (fflush(spool) != 0 || fseeko(spool, 0, SEEK_SET) != 0) fail_errno("rewinding compressed blocks");

    uint8_t source_digest[32];
    sha_bytes(source, source_size, source_digest);
    char *output_temp = NULL;
    FILE *output = create_temp(output_path, "part", &output_temp);
    write_exact(output, "LBC2", 4);
    put_u8(output, 4);
    put_u32(output, chunk_size);
    put_u64(output, source_size);
    write_exact(output, source_digest, sizeof(source_digest));
    put_u32(output, block_count);
    put_u32(output, unique_count);
    put_u32(output, run_count);
    for (uint32_t i = 0; i < run_count; ++i) {
        put_u32(output, runs[i].id);
        put_u32(output, runs[i].count);
    }
    uint8_t copy_buffer[65536];
    for (;;) {
        size_t n = fread(copy_buffer, 1, sizeof(copy_buffer), spool);
        if (n != 0) write_exact(output, copy_buffer, n);
        if (n < sizeof(copy_buffer)) {
            if (ferror(spool)) fail_errno("reading compressed block spool");
            break;
        }
    }
    if (fclose(spool) != 0) fail_errno("closing compressed block spool");
    release_owned(spool_path, 1);
    publish_temp(output, output_temp, output_path);

    struct stat in_st;
    if (stat(input_path, &in_st) == 0) {
        (void)chmod(output_path, in_st.st_mode & 0777);
        struct utimbuf ub;
        ub.actime = in_st.st_atime;
        ub.modtime = in_st.st_mtime;
        (void)utime(output_path, &ub);
    }

    struct stat st;
    if (stat(output_path, &st) != 0) fail_errno("measuring compressed output");
    double reduction = source_size == 0 ? 0.0 : 100.0 * (1.0 - (double)st.st_size / (double)source_size);
    if (!quiet_api) printf("input_bytes=%zu\ncompressed_bytes=%" PRIu64 "\nreduction_percent=%.6f\nsource_sha256=", 
           source_size, (uint64_t)st.st_size, reduction);
    if (!quiet_api) print_digest(source_digest);
    if (!quiet_api) printf("\nblocks=%" PRIu32 " unique_blocks=%" PRIu32 " runs=%" PRIu32 "\n", block_count, unique_count, run_count);
    free(source); free(slots); free(block_ids); free(unique); free(runs);
}

static inline uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           (uint32_t)p[3];
}

static int decode_huffman(const uint8_t *packed, size_t packed_length, uint64_t bit_count,
                          const uint64_t frequencies[256], uint8_t *output, uint32_t raw_length) {
    if (bit_count > (uint64_t)packed_length * 8U || bit_count > UINT64_MAX - 7U ||
        packed_length != (size_t)((bit_count + 7U) / 8U)) return 0;
    HuffNode nodes[511];
    int root;
    unsigned symbols;
    build_huffman_tree(frequencies, nodes, &root, &symbols);
    if (symbols < 2 || root < 0) return 0;
    HuffCodes codes = {{0},{0}};
    if (!assign_codes(nodes, root, 0, 0, &codes)) return 0;
    enum { FAST_BITS = 12, FAST_SIZE = 1 << FAST_BITS };
    uint16_t fast[FAST_SIZE] = {0};
    for (unsigned symbol = 0; symbol < 256; ++symbol) {
        unsigned length = codes.length[symbol];
        if (length == 0 || length > FAST_BITS) continue;
        unsigned first = (unsigned)codes.code[symbol] << (FAST_BITS - length);
        unsigned count = 1U << (FAST_BITS - length);
        for (unsigned i = first; i < first + count; ++i) {
            fast[i] = (uint16_t)((length << 8) | symbol);
        }
    }
    uint64_t observed[256] = {0};
    uint64_t bit_buf = 0;
    unsigned bits_in_buf = 0;
    size_t byte_pos = 0;
    uint64_t bits_consumed = 0;
    uint32_t out = 0;

    while (bits_in_buf <= 56 && byte_pos < packed_length) {
        bit_buf |= ((uint64_t)packed[byte_pos++]) << (56 - bits_in_buf);
        bits_in_buf += 8;
    }

    while (out < raw_length) {
        if (bits_in_buf <= 32) {
            if (byte_pos + 4 <= packed_length) {
                uint32_t b4 = read_be32(packed + byte_pos);
                bit_buf |= ((uint64_t)b4) << (32 - bits_in_buf);
                bits_in_buf += 32;
                byte_pos += 4;
            } else {
                while (bits_in_buf <= 56 && byte_pos < packed_length) {
                    bit_buf |= ((uint64_t)packed[byte_pos++]) << (56 - bits_in_buf);
                    bits_in_buf += 8;
                }
            }
        }

        uint64_t remaining = bit_count - bits_consumed;
        if (remaining >= FAST_BITS) {
            unsigned prefix = (unsigned)(bit_buf >> (64 - FAST_BITS)) & (FAST_SIZE - 1U);
            uint16_t entry = fast[prefix];
            if (entry != 0) {
                unsigned len = entry >> 8;
                uint8_t symbol = (uint8_t)entry;
                bit_buf <<= len;
                bits_in_buf -= len;
                bits_consumed += len;
                output[out++] = symbol;
                ++observed[symbol];
                continue;
            }
        }

        int node = root;
        while (nodes[node].symbol < 0) {
            if (bits_consumed >= bit_count || bits_in_buf == 0) return 0;
            unsigned bit = (unsigned)(bit_buf >> 63);
            bit_buf <<= 1;
            --bits_in_buf;
            ++bits_consumed;
            node = bit ? nodes[node].right : nodes[node].left;
            if (node < 0 || node >= 511) return 0;
        }
        uint8_t symbol = (uint8_t)nodes[node].symbol;
        output[out++] = symbol;
        ++observed[symbol];
    }
    if (bits_consumed != bit_count) return 0;
    for (unsigned i = 0; i < 256; ++i) if (observed[i] != frequencies[i]) return 0;
    return 1;
}

static void decompress_file(const char *input_path, const char *output_path) {
    if (!opt_test) {
        if (output_path == NULL) fail("missing output path for decompression");
        verify_new_output(output_path);
    }
    FILE *input = fopen(input_path, "rb");
    if (input == NULL) fail_errno("opening compressed input");
    uint8_t magic[4], expected_digest[32];
    read_exact(input, magic, sizeof(magic));
    uint8_t version = get_u8(input);
    int legacy = memcmp(magic, "LBC1", 4) == 0 && version == 1;
    int current_v2 = memcmp(magic, "LBC2", 4) == 0 && version == 2;
    int current_v3 = memcmp(magic, "LBC2", 4) == 0 && version == 3;
    int current_v4 = memcmp(magic, "LBC2", 4) == 0 && version == 4;
    int current = current_v2 || current_v3 || current_v4;
    if (!legacy && !current) fail("unsupported LBC file");
    uint32_t chunk_size = get_u32(input);
    uint64_t source_size = get_u64(input);
    read_exact(input, expected_digest, sizeof(expected_digest));
    uint32_t block_count = get_u32(input);
    uint32_t unique_count = get_u32(input);
    uint32_t run_count = get_u32(input);
    if (chunk_size == 0 || source_size > MAX_INPUT) fail("invalid LBC1 geometry or safety limit");
    uint64_t expected_blocks = source_size == 0 ? 0 : (source_size + (uint64_t)chunk_size - 1U) / chunk_size;
    if (expected_blocks != block_count || block_count > MAX_BLOCKS ||
        unique_count > block_count || run_count > block_count || (block_count == 0 && (unique_count != 0 || run_count != 0)) ||
        (block_count != 0 && (unique_count == 0 || run_count == 0)))
        fail("invalid LBC1 geometry or safety limit");

    Run *runs = calloc(run_count == 0 ? 1 : run_count, sizeof(*runs));
    uint8_t **unique_data = calloc(unique_count == 0 ? 1 : unique_count, sizeof(*unique_data));
    uint32_t *unique_lengths = calloc(unique_count == 0 ? 1 : unique_count, sizeof(*unique_lengths));
    uint8_t *referenced = calloc(unique_count == 0 ? 1 : unique_count, 1);
    if (runs == NULL || unique_data == NULL || unique_lengths == NULL || referenced == NULL)
        fail("out of memory reading LBC1 index");
    uint64_t blocks_in_runs = 0;
    for (uint32_t i = 0; i < run_count; ++i) {
        runs[i].id = get_u32(input);
        runs[i].count = get_u32(input);
        if (runs[i].id >= unique_count || runs[i].count == 0 || UINT64_MAX - blocks_in_runs < runs[i].count)
            fail("invalid LBC1 run index");
        blocks_in_runs += runs[i].count;
        referenced[runs[i].id] = 1;
    }
    if (blocks_in_runs != block_count) fail("LBC1 run count does not match block count");

    uint64_t unique_total = 0;
    for (uint32_t id = 0; id < unique_count; ++id) {
        uint32_t raw_length = get_u32(input);
        uint8_t mode = get_u8(input);
        uint64_t bit_count = get_u64(input);
        uint64_t payload_length64 = get_u64(input);
        if (raw_length == 0 || raw_length > chunk_size || raw_length > source_size ||
            unique_total > source_size - raw_length || payload_length64 > raw_length || payload_length64 > SIZE_MAX)
            fail("invalid LBC1 chunk size");
        unique_total += raw_length;
        size_t payload_length = (size_t)payload_length64;
        uint8_t *decoded = malloc(raw_length);
        if (decoded == NULL) fail("out of memory decoding LBC1 chunk");
        if (mode == 0) {
            if (bit_count != 0 || payload_length != raw_length) fail("invalid raw LBC chunk");
            read_exact(input, decoded, raw_length);
        } else if (mode == 3 && current) {
            if (raw_length > MAX_LZ_CHUNK || bit_count == 0 ||
                bit_count > MAX_LZ_TOKEN_BYTES || bit_count != payload_length64)
                fail("invalid LZ-coded LBC chunk header");
            uint8_t *token_data = malloc(payload_length);
            if (token_data == NULL) fail("out of memory reading LZ payload");
            read_exact(input, token_data, payload_length);
            int valid = decode_lz_tokens(token_data, payload_length, decoded, raw_length);
            free(token_data);
            if (!valid) fail("invalid LZ-coded LBC chunk");
        } else if (mode == 1 || (mode == 2 && current) ||
                   ((mode == 4 || mode == 5) && (current_v3 || current_v4)) ||
                   ((mode == 6 || mode == 7) && current_v4)) {
            if (payload_length == 0 || bit_count == 0 || bit_count > payload_length64 * 8U ||
                bit_count > UINT64_MAX - 7U || payload_length != (size_t)((bit_count + 7U) / 8U))
                fail("invalid Huffman LBC chunk header");
            int lz_huffman = mode == 2 || mode == 4 || mode == 6;
            int bwt_huffman = mode == 5 || mode == 7;
            uint32_t bwt_primary = bwt_huffman ? get_u32(input) : 0;
            uint64_t frequencies[256] = {0}, sum = 0;
            if (mode == 4 || mode == 5 || mode == 6 || mode == 7) {
                unsigned symbol_count = ((unsigned)get_u8(input) << 8) | get_u8(input);
                if (symbol_count < 2U || symbol_count > 256U)
                    fail("invalid sparse Huffman symbol count");
                int previous_symbol = -1;
                for (unsigned i = 0; i < symbol_count; ++i) {
                    unsigned symbol = get_u8(input);
                    uint32_t frequency = mode >= 6 ? get_varint(input) : get_u32(input);
                    if ((int)symbol <= previous_symbol || frequency == 0 ||
                        UINT64_MAX - sum < frequency)
                        fail("invalid sparse Huffman frequency table");
                    previous_symbol = (int)symbol;
                    frequencies[symbol] = frequency;
                    sum += frequency;
                }
            } else {
                for (unsigned i = 0; i < 256; ++i) {
                    frequencies[i] = get_u64(input);
                    if (UINT64_MAX - sum < frequencies[i]) fail("LBC frequency overflow");
                    sum += frequencies[i];
                }
            }
            if ((mode == 1 && sum != raw_length) ||
                (lz_huffman && (raw_length > MAX_LZ_CHUNK || sum == 0 ||
                                sum > MAX_LZ_TOKEN_BYTES || sum > UINT32_MAX)) ||
                (bwt_huffman && (raw_length > MAX_BWT_CHUNK || sum == 0 ||
                                 sum > MAX_BWT_TOKEN_BYTES || sum > UINT32_MAX)))
                fail("LBC frequency total mismatch");
            uint8_t *packed = malloc(payload_length);
            uint8_t *token_data = (lz_huffman || bwt_huffman) ?
                malloc((size_t)sum) : decoded;
            if (packed == NULL || token_data == NULL) fail("out of memory reading Huffman payload");
            read_exact(input, packed, payload_length);
            int valid = decode_huffman(packed, payload_length, bit_count, frequencies,
                                       token_data, (uint32_t)sum);
            free(packed);
            if (valid && lz_huffman)
                valid = decode_lz_tokens(token_data, (size_t)sum, decoded, raw_length);
            if (valid && bwt_huffman)
                valid = decode_bwt_tokens(token_data, (size_t)sum, bwt_primary,
                                          decoded, raw_length);
            if (!valid) fail("invalid entropy-coded LBC chunk");
            if (lz_huffman || bwt_huffman) free(token_data);
        } else if (mode == 8 && (current_v4 || current)) {
            if (payload_length == 0 || bit_count > 1 || payload_length > raw_length)
                fail("invalid range-coded LBC chunk header");
            uint8_t *packed = malloc(payload_length);
            if (packed == NULL) fail("out of memory reading range-coded payload");
            read_exact(input, packed, payload_length);
            int valid = 0;
            if (bit_count == 0) {
                valid = decode_range_order0(packed, payload_length, decoded, raw_length);
            } else if (bit_count == 1) {
                valid = decode_range_order1(packed, payload_length, decoded, raw_length);
            }
            free(packed);
            if (!valid) fail("invalid range-coded LBC chunk");
        } else if (mode == 9 && (current_v4 || current)) {
            if (payload_length == 0 || bit_count > 1 || payload_length > raw_length)
                fail("invalid bit-lz coded LBC chunk header");
            uint8_t *packed = malloc(payload_length);
            if (packed == NULL) fail("out of memory reading bit-lz payload");
            read_exact(input, packed, payload_length);
            int valid = decode_bit_lz(packed, payload_length, decoded, raw_length);
            if (valid && bit_count == 1) {
                lbc_bcj_x86_filter(decoded, raw_length, 0);
            }
            free(packed);
            if (!valid) fail("invalid bit-lz coded LBC chunk");
#ifndef LBC_TEST_LZ_SELECTION
        } else if (mode == 10 && (current_v4 || current)) {
            if (payload_length == 0 || payload_length > raw_length)
                fail("invalid cmix coded LBC chunk header");
            uint8_t *packed = malloc(payload_length);
            if (packed == NULL) fail("out of memory reading cmix payload");
            read_exact(input, packed, payload_length);
            int bcj = bit_count & 1;
            int stride = (bit_count >> 8) & 0xFF;
            int tbits = (bit_count >> 16) & 0xFF;
            if (stride < 1 || stride > 64) stride = 4;
            if (tbits < 12 || tbits > 23) tbits = 22;
            int valid = decode_cmix(packed, payload_length, decoded, raw_length, tbits, stride);
            if (bcj && valid) {
                lbc_bcj_x86_filter(decoded, raw_length, 0);
            }
            free(packed);
            if (!valid) fail("invalid cmix coded LBC chunk");
#endif
        } else {
            fail("unknown LBC chunk method");
        }
        unique_data[id] = decoded;
        unique_lengths[id] = raw_length;
    }
    if (fgetc(input) != EOF || ferror(input)) fail("trailing data or read error in LBC1 file");
    if (fclose(input) != 0) fail_errno("closing compressed input");
    for (uint32_t id = 0; id < unique_count; ++id) if (!referenced[id]) fail("unreferenced LBC1 chunk");

    char *output_temp = NULL;
    FILE *output = NULL;
    if (!opt_test) {
        output = create_temp(output_path, "part", &output_temp);
    }
    Sha256 sha;
    sha_init(&sha);
    uint64_t written = 0;
    uint32_t block_index = 0;
    for (uint32_t r = 0; r < run_count; ++r) {
        uint32_t id = runs[r].id;
        for (uint32_t n = 0; n < runs[r].count; ++n) {
            uint64_t offset = (uint64_t)block_index * chunk_size;
            uint64_t remaining = source_size - offset;
            uint32_t expected_length = remaining > chunk_size ? chunk_size : (uint32_t)remaining;
            if (unique_lengths[id] != expected_length) fail("LBC1 block length does not match output position");
            if (output != NULL) write_exact(output, unique_data[id], unique_lengths[id]);
            sha_update(&sha, unique_data[id], unique_lengths[id]);
            written += unique_lengths[id];
            ++block_index;
        }
    }
    uint8_t actual_digest[32];
    sha_final(&sha, actual_digest);
    if (written != source_size || block_index != block_count || memcmp(actual_digest, expected_digest, 32) != 0)
        fail("LBC1 output size or SHA-256 verification failed");
    if (output != NULL) {
        publish_temp(output, output_temp, output_path);
        struct stat arc_st;
        if (stat(input_path, &arc_st) == 0) {
            (void)chmod(output_path, arc_st.st_mode & 0777);
            struct utimbuf ub;
            ub.actime = arc_st.st_atime;
            ub.modtime = arc_st.st_mtime;
            (void)utime(output_path, &ub);
        }
    }
    if (opt_test) {
        if (!quiet_api) printf("%s: OK (SHA-256 verified, %" PRIu64 " bytes)\n", input_path, written);
    } else {
        if (!quiet_api) printf("output_bytes=%" PRIu64 "\nsha256=", written);
        if (!quiet_api) print_digest(actual_digest);
        if (!quiet_api) printf("\nverified=true\n");
    }
    for (uint32_t id = 0; id < unique_count; ++id) free(unique_data[id]);
    free(unique_data); free(unique_lengths); free(referenced); free(runs);
}

#ifndef LBC_NO_MAIN
static uint64_t splitmix64_next(uint64_t *state) {
    uint64_t z = (*state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void generate_file(const char *output_path, unsigned payload_mib, unsigned repeats, uint64_t seed) {
    verify_new_output(output_path);
    if (payload_mib == 0 || payload_mib > 100 || repeats < 2) fail("generator requires payload MiB 1..100 and repeats >=2");
    size_t payload_length = (size_t)payload_mib * (size_t)MIB;
    uint64_t encoded64 = ((uint64_t)payload_length + 2U) / 3U * 4U;
    if (encoded64 > SIZE_MAX - 5U) fail("generated record too large");
    uint64_t record64 = encoded64 + 5U;
    uint64_t total64 = record64 * repeats;
    if (total64 > MAX_INPUT) fail("generated input exceeds the 600 MiB safety limit");
    uint8_t *payload = malloc(payload_length);
    uint8_t *encoded = malloc((size_t)encoded64);
    if (payload == NULL || encoded == NULL) fail("out of memory generating deterministic sample");
    uint64_t state = seed;
    size_t pos = 0;
    while (pos < payload_length) {
        uint64_t value = splitmix64_next(&state);
        for (unsigned i = 0; i < 8 && pos < payload_length; ++i, ++pos)
            payload[pos] = (uint8_t)(value >> (8U*i));
    }
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t out = 0;
    for (size_t i = 0; i < payload_length; i += 3) {
        uint32_t a = payload[i];
        uint32_t b = i + 1 < payload_length ? payload[i+1] : 0;
        uint32_t c = i + 2 < payload_length ? payload[i+2] : 0;
        encoded[out++] = (uint8_t)alphabet[a >> 2];
        encoded[out++] = (uint8_t)alphabet[((a & 3U) << 4) | (b >> 4)];
        encoded[out++] = (uint8_t)(i + 1 < payload_length ? alphabet[((b & 15U) << 2) | (c >> 6)] : '=');
        encoded[out++] = (uint8_t)(i + 2 < payload_length ? alphabet[c & 63U] : '=');
    }
    uint8_t *record = malloc((size_t)record64);
    if (record == NULL) fail("out of memory building source-code record");
    memcpy(record, ": '", 3);
    memcpy(record + 3, encoded, (size_t)encoded64);
    record[3U + (size_t)encoded64] = '\'';
    record[4U + (size_t)encoded64] = '\n';
    free(encoded);
    free(payload);

    char *temporary = NULL;
    FILE *output = create_temp(output_path, "part", &temporary);
    Sha256 sha;
    sha_init(&sha);
    for (unsigned i = 0; i < repeats; ++i) {
        write_exact(output, record, (size_t)record64);
        sha_update(&sha, record, (size_t)record64);
    }
    uint8_t digest[32];
    sha_final(&sha, digest);
    free(record);
    publish_temp(output, temporary, output_path);
    printf("input_bytes=%" PRIu64 "\nsha256=", total64);
    print_digest(digest);
    printf("\nrecord_bytes=%" PRIu64 " repeats=%u seed=%" PRIu64 "\n", record64, repeats, seed);
}

static void generate_bytes_file(const char *output_path, uint64_t length, uint64_t seed) {
    verify_new_output(output_path);
    if (length > MAX_INPUT) fail("generated input exceeds the 600 MiB safety limit");
    char *temporary = NULL;
    FILE *output = create_temp(output_path, "part", &temporary);
    uint8_t buffer[65536];
    uint64_t state = seed;
    uint64_t remaining = length;
    Sha256 sha;
    sha_init(&sha);
    while (remaining != 0) {
        size_t take = remaining > sizeof(buffer) ? sizeof(buffer) : (size_t)remaining;
        size_t pos = 0;
        while (pos < take) {
            uint64_t value = splitmix64_next(&state);
            for (unsigned i = 0; i < 8 && pos < take; ++i, ++pos)
                buffer[pos] = (uint8_t)(value >> (8U*i));
        }
        write_exact(output, buffer, take);
        sha_update(&sha, buffer, take);
        remaining -= take;
    }
    uint8_t digest[32];
    sha_final(&sha, digest);
    publish_temp(output, temporary, output_path);
    printf("input_bytes=%" PRIu64 "\nsha256=", length);
    print_digest(digest);
    putchar('\n');
}

static void hash_file(const char *path) {
    FILE *input = fopen(path, "rb");
    if (input == NULL) fail_errno("opening file for SHA-256");
    uint8_t buffer[65536], digest[32];
    Sha256 sha;
    sha_init(&sha);
    for (;;) {
        size_t n = fread(buffer, 1, sizeof(buffer), input);
        if (n != 0) sha_update(&sha, buffer, n);
        if (n < sizeof(buffer)) {
            if (ferror(input)) fail_errno("reading file for SHA-256");
            break;
        }
    }
    if (fclose(input) != 0) fail_errno("closing hashed file");
    sha_final(&sha, digest);
    print_digest(digest);
    putchar('\n');
}

static uint64_t parse_u64(const char *text, const char *field) {
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        fprintf(stderr, "lbc: invalid %s\n", field);
        exit(EXIT_FAILURE);
    }
    return (uint64_t)value;
}

enum {
    ACT_NONE = 0,
    ACT_COMPRESS,
    ACT_DECOMPRESS,
    ACT_TEST,
    ACT_INFO,
    ACT_SHA256
};

static void usage(void) {
    fprintf(stderr,
        "=================================================================\n"
        "  LBC (Lossless Block Codec) - Ultra High-Ratio Compression Engine\n"
        "=================================================================\n"
        "Usage:\n"
        "  lbc [options] [command] <input> [output] [chunk_bytes]\n"
        "\n"
        "Commands:\n"
        "  c, compress   <input> [output.lbc]   Compress file (default)\n"
        "  d, decompress <archive.lbc> [output] Decompress archive\n"
        "  t, test       <archive.lbc>          Test archive integrity (SHA-256)\n"
        "  i, info       <archive.lbc>          Display archive metadata and ratio\n"
        "  sha256        <file>                 Compute SHA-256 digest\n"
        "  generate      <output> <mib> <rep> <seed> Generate test fixture\n"
        "\n"
        "Options:\n"
        "  -1 .. -9      Compression preset (1=fast, 9=ultra ratio, default: 9)\n"
        "  --fast        Fastest compression (-1)\n"
        "  --best        Maximum compression ratio (-9)\n"
        "  -f, --force   Force overwrite of existing output file\n"
        "  -k, --keep    Keep input files (default behavior)\n"
        "  -t, --test    Test integrity of compressed archive\n"
        "  -q, --quiet   Suppress informative messages\n"
        "  -v, --verbose Verbose output\n"
        "  -o <path>     Write output to specified file\n"
        "  -h, --help    Display this help text\n"
        "\n"
        "Default archive extension: .lbc\n");
}

static char *lbc_auto_out_compress(const char *in) {
    size_t len = strlen(in);
    char *out = malloc(len + 5);
    if (!out) fail("out of memory allocating output path");
    memcpy(out, in, len);
    memcpy(out + len, ".lbc", 5);
    return out;
}

static char *lbc_auto_out_decompress(const char *in) {
    size_t len = strlen(in);
    if (len > 4 && strcmp(in + len - 4, ".lbc") == 0) {
        char *out = malloc(len - 3);
        if (!out) fail("out of memory allocating output path");
        memcpy(out, in, len - 4);
        out[len - 4] = '\0';
        return out;
    }
    char *out = malloc(len + 5);
    if (!out) fail("out of memory allocating output path");
    memcpy(out, in, len);
    memcpy(out + len, ".out", 5);
    return out;
}

#ifdef LBC_CLI_NAME
int LBC_CLI_NAME(int argc, char **argv) {
#else
int main(int argc, char **argv) {
#endif
    (void)atexit(cleanup_owned);
    if (argc < 2) {
        usage();
        return EXIT_FAILURE;
    }

    if (argc == 6 && strcmp(argv[1], "generate") == 0) {
        uint64_t payload = parse_u64(argv[3], "payload MiB");
        uint64_t repeats = parse_u64(argv[4], "repeat count");
        uint64_t seed = parse_u64(argv[5], "seed");
        if (payload > UINT32_MAX || repeats > UINT32_MAX) fail("generator parameter overflow");
        generate_file(argv[2], (unsigned)payload, (unsigned)repeats, seed);
        return EXIT_SUCCESS;
    }
    if (argc == 5 && strcmp(argv[1], "generate-bytes") == 0) {
        generate_bytes_file(argv[2], parse_u64(argv[3], "byte count"), parse_u64(argv[4], "seed"));
        return EXIT_SUCCESS;
    }

    int action = ACT_NONE;
    const char *pos_args[8];
    int pos_count = 0;
    const char *explicit_out = NULL;

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (arg[0] == '-' && arg[1] != '\0') {
            if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
                usage();
                return EXIT_SUCCESS;
            }
            if (strcmp(arg, "--force") == 0) { opt_force = 1; continue; }
            if (strcmp(arg, "--test") == 0) { opt_test = 1; action = ACT_TEST; continue; }
            if (strcmp(arg, "--keep") == 0) { continue; }
            if (strcmp(arg, "--quiet") == 0) { quiet_api = 1; continue; }
            if (strcmp(arg, "--verbose") == 0) { opt_verbose = 1; continue; }
            if (strcmp(arg, "--fast") == 0) { opt_level = 1; continue; }
            if (strcmp(arg, "--best") == 0) { opt_level = 9; continue; }
            if (strcmp(arg, "--compress") == 0) { action = ACT_COMPRESS; continue; }
            if (strcmp(arg, "--decompress") == 0) { action = ACT_DECOMPRESS; continue; }
            if (strcmp(arg, "--info") == 0 || strcmp(arg, "--list") == 0) { action = ACT_INFO; continue; }
            if (strncmp(arg, "--output=", 9) == 0) { explicit_out = arg + 9; continue; }
            if (arg[1] == '-') fail("unknown option");

            for (int j = 1; arg[j] != '\0'; ++j) {
                char c = arg[j];
                if (c >= '1' && c <= '9') {
                    opt_level = c - '0';
                } else if (c == 'f') {
                    opt_force = 1;
                } else if (c == 't') {
                    opt_test = 1;
                    action = ACT_TEST;
                } else if (c == 'k') {
                    /* keep input files */
                } else if (c == 'q') {
                    quiet_api = 1;
                } else if (c == 'v') {
                    opt_verbose = 1;
                } else if (c == 'c') {
                    action = ACT_COMPRESS;
                } else if (c == 'd' || c == 'x') {
                    action = ACT_DECOMPRESS;
                } else if (c == 'i' || c == 'l') {
                    action = ACT_INFO;
                } else if (c == 'h') {
                    usage();
                    return EXIT_SUCCESS;
                } else if (c == 'o') {
                    if (arg[j + 1] != '\0') {
                        explicit_out = &arg[j + 1];
                        break;
                    } else if (i + 1 < argc) {
                        explicit_out = argv[++i];
                        break;
                    } else {
                        fail("missing argument after -o");
                    }
                } else {
                    fail("unknown option flag");
                }
            }
            continue;
        }

        if (pos_count == 0 && action == ACT_NONE) {
            if (strcmp(arg, "compress") == 0 || strcmp(arg, "c") == 0) {
                action = ACT_COMPRESS;
                continue;
            }
            if (strcmp(arg, "decompress") == 0 || strcmp(arg, "d") == 0 || strcmp(arg, "x") == 0) {
                action = ACT_DECOMPRESS;
                continue;
            }
            if (strcmp(arg, "test") == 0 || strcmp(arg, "t") == 0) {
                action = ACT_TEST;
                opt_test = 1;
                continue;
            }
            if (strcmp(arg, "info") == 0 || strcmp(arg, "i") == 0) {
                action = ACT_INFO;
                continue;
            }
            if (strcmp(arg, "sha256") == 0) {
                action = ACT_SHA256;
                continue;
            }
        }
        if (pos_count < 8) {
            pos_args[pos_count++] = arg;
        }
    }

    if (opt_verbose) {
        fprintf(stderr, "lbc: level=%d force=%d test=%d\n", opt_level, opt_force, opt_test);
    }

    if (action == ACT_SHA256) {
        if (pos_count != 1) fail("sha256 requires exactly one file path");
        hash_file(pos_args[0]);
        return EXIT_SUCCESS;
    }

    if (action == ACT_INFO) {
        if (pos_count != 1) fail("info requires an archive path");
        const char *info_path = pos_args[0];
        FILE *f = fopen(info_path, "rb");
        if (!f) fail_errno("opening archive for info");
        uint8_t magic[4];
        read_exact(f, magic, 4);
        if (memcmp(magic, "LBC2", 4) != 0 && memcmp(magic, "LBC1", 4) != 0) fail("not a valid LBC archive");
        uint8_t ver = get_u8(f);
        uint32_t chunk_sz = get_u32(f);
        uint64_t src_sz = get_u64(f);
        uint8_t digest[32];
        read_exact(f, digest, 32);
        uint32_t blk_cnt = get_u32(f);
        uint32_t unq_cnt = get_u32(f);
        uint32_t run_cnt = get_u32(f);
        fclose(f);
        struct stat st;
        if (stat(info_path, &st) != 0) fail_errno("stat archive");
        double ratio = src_sz == 0 ? 0.0 : ((double)st.st_size / (double)src_sz) * 100.0;
        printf("=================================================================\n");
        printf("  LBC Archive Information: %s\n", info_path);
        printf("=================================================================\n");
        printf("  Format Version:    %.4s v%u\n", magic, ver);
        printf("  Original Size:     %" PRIu64 " bytes\n", src_sz);
        printf("  Archive Size:      %" PRIu64 " bytes (%.2f%% of original)\n", (uint64_t)st.st_size, ratio);
        printf("  Chunk Size:        %" PRIu32 " bytes\n", chunk_sz);
        printf("  Block Structure:   %" PRIu32 " blocks (%" PRIu32 " unique, %" PRIu32 " runs)\n", blk_cnt, unq_cnt, run_cnt);
        printf("  Original SHA-256:  ");
        print_digest(digest);
        printf("\n=================================================================\n");
        return EXIT_SUCCESS;
    }

    if (action == ACT_TEST || opt_test) {
        if (pos_count < 1) fail("test requires an archive path");
        opt_test = 1;
        for (int p = 0; p < pos_count; ++p) {
            decompress_file(pos_args[p], NULL);
        }
        return EXIT_SUCCESS;
    }

    if (pos_count == 0) {
        usage();
        return EXIT_FAILURE;
    }

    if (action == ACT_NONE) {
        const char *p = pos_args[0];
        size_t l = strlen(p);
        if (l > 4 && strcmp(p + l - 4, ".lbc") == 0) {
            action = ACT_DECOMPRESS;
        } else {
            action = ACT_COMPRESS;
        }
    }

    if (action == ACT_COMPRESS) {
        const char *in_path = pos_args[0];
        char *allocated_out = NULL;
        const char *out_path = explicit_out;
        uint64_t chunk = DEFAULT_CHUNK;
        if (!out_path) {
            if (pos_count >= 2) {
                out_path = pos_args[1];
                if (pos_count >= 3) chunk = parse_u64(pos_args[2], "chunk size");
            } else {
                allocated_out = lbc_auto_out_compress(in_path);
                out_path = allocated_out;
            }
        } else {
            if (pos_count >= 2) chunk = parse_u64(pos_args[1], "chunk size");
        }
        if (chunk == 0 || chunk > UINT32_MAX) fail("chunk size must fit in uint32 and be nonzero");
        compress_file(in_path, out_path, (uint32_t)chunk);
        if (allocated_out) free(allocated_out);
        return EXIT_SUCCESS;
    }

    if (action == ACT_DECOMPRESS) {
        const char *in_path = pos_args[0];
        char *allocated_out = NULL;
        const char *out_path = explicit_out;
        if (!out_path) {
            if (pos_count >= 2) {
                out_path = pos_args[1];
            } else {
                allocated_out = lbc_auto_out_decompress(in_path);
                out_path = allocated_out;
            }
        }
        decompress_file(in_path, out_path);
        if (allocated_out) free(allocated_out);
        return EXIT_SUCCESS;
    }

    usage();
    return EXIT_FAILURE;
}
#endif


static char *api_temp_path(void) {
    if (api_dir == NULL) {
        const char *tmp = getenv("TMPDIR");
        if (!tmp || !*tmp) tmp = "/tmp";
        size_t dlen = strlen(tmp) + 32;
        api_dir = malloc(dlen);
        if (!api_dir) fail("out of memory creating API directory");
        snprintf(api_dir, dlen, "%s/lbc-api-XXXXXX", tmp);
        if (!mkdtemp(api_dir)) {
            free(api_dir); api_dir = NULL;
            fail_errno("creating secure API temporary directory");
        }
    }
    size_t plen = strlen(api_dir) + 32;
    char *p = malloc(plen);
    if (!p) fail("out of memory creating temporary path");
    snprintf(p, plen, "%s/f%u", api_dir, ++temp_serial);
    register_owned(p);
    return p;
}

static void api_write_file(const char *path, const void *data, size_t n) {
    FILE *f = fopen(path, "wb"); if (!f) fail_errno("creating API input");
    if (n && fwrite(data, 1, n, f) != n) fail_errno("writing API input");
    if (fclose(f) != 0) fail_errno("closing API input");
}

lbc_status lbc_compress(const void *input, size_t n, size_t chunk, void **out, size_t *out_n) {
    if (out) *out = NULL;
    if (out_n) *out_n = 0;
    if (!out || !out_n || (!input && n) || chunk == 0 || chunk > UINT32_MAX) return LBC_ERROR_ARGUMENT;
    if (n > LBC_MAX_INPUT_BYTES) return LBC_ERROR_LIMIT;
    jmp_buf env; api_tracking = 1; api_jump = &env; api_status = LBC_ERROR_INTERNAL; quiet_api = 1; lbc_status s = LBC_OK;
    if (setjmp(env) != 0) { cleanup_api_resources(); api_jump = NULL; quiet_api = 0; return (lbc_status)api_status; }
    char *src = api_temp_path(), *dst = api_temp_path();
    api_write_file(src, input, n);
    compress_file(src, dst, (uint32_t)chunk);
    size_t z = 0; uint8_t *data = load_file(dst, &z);
    release_owned(src, 1); release_owned(dst, 1);
    *out = data; *out_n = z; api_allocation_count = 0; api_tracking = 0; api_jump = NULL; quiet_api = 0; return s;
}

lbc_status lbc_decompress(const void *archive, size_t n, void **out, size_t *out_n) {
    if (out) *out = NULL;
    if (out_n) *out_n = 0;
    if (!out || !out_n || (!archive && n)) return LBC_ERROR_ARGUMENT;
    if (n > LBC_MAX_INPUT_BYTES) return LBC_ERROR_LIMIT;
    jmp_buf env; api_tracking = 1; api_jump = &env; api_status = LBC_ERROR_INTERNAL; quiet_api = 1; lbc_status s = LBC_OK;
    if (setjmp(env) != 0) { cleanup_api_resources(); api_jump = NULL; quiet_api = 0; return (lbc_status)api_status; }
    char *src = api_temp_path(), *dst = api_temp_path();
    api_write_file(src, archive, n);
    decompress_file(src, dst);
    size_t z = 0; uint8_t *data = load_file(dst, &z);
    release_owned(src, 1); release_owned(dst, 1);
    *out = data; *out_n = z; api_allocation_count = 0; api_tracking = 0; api_jump = NULL; quiet_api = 0; return s;
}

static lbc_status api_file_call(const char *src, const char *dst, size_t chunk, int decompress) {
    if (!src || !dst || !*src || !*dst || strcmp(src, dst) == 0) return LBC_ERROR_ARGUMENT;
    jmp_buf env; api_tracking = 1; api_jump = &env; api_status = LBC_ERROR_INTERNAL; quiet_api = 1;
    opt_force = 0; opt_test = 0; opt_level = 9;
    if (setjmp(env) != 0) { cleanup_api_resources(); api_jump = NULL; quiet_api = 0; return (lbc_status)api_status; }
    verify_new_output(dst);
    if (decompress) decompress_file(src, dst);
    else { if (!chunk || chunk > UINT32_MAX) { api_jump = NULL; quiet_api = 0; return LBC_ERROR_ARGUMENT; } compress_file(src, dst, (uint32_t)chunk); }
    api_allocation_count = 0; api_tracking = 0; api_jump = NULL; quiet_api = 0; return LBC_OK;
}
lbc_status lbc_compress_file(const char *s, const char *d, size_t c) { return api_file_call(s,d,c,0); }
lbc_status lbc_decompress_file(const char *s, const char *d) { return api_file_call(s,d,0,1); }
void lbc_free(void *p) { free(p); }
const char *lbc_status_string(lbc_status s) {
    static const char *const names[] = {"ok","invalid argument","limit exceeded","invalid format","I/O error","out of memory","destination exists","unsupported format","internal error"};
    return (unsigned)s < sizeof(names)/sizeof(names[0]) ? names[s] : "unknown error";
}
