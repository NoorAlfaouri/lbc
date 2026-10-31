/* Verify selection when a wider greedy search produces a larger LZ record. */
#define LBC_TEST_LZ_SELECTION 1
#define main lbc_program_main
#include "../lbc.c"
#undef main

static uint32_t random_state = 853412U;

static uint8_t next_byte(void) {
    random_state ^= random_state << 13;
    random_state ^= random_state >> 17;
    random_state ^= random_state << 5;
    return (uint8_t)(32U + (random_state & 63U));
}

static uint64_t lz_record_size(const uint8_t *input, uint32_t length, uint32_t window) {
    size_t token_length = 0, payload_length = 0;
    uint64_t frequencies[256] = {0}, bits = 0, sparse_size = 2;
    uint8_t *tokens = encode_lz_tokens(input, length, window, &token_length);
    if (tokens == NULL) return UINT64_MAX;
    for (size_t i = 0; i < token_length; ++i) ++frequencies[tokens[i]];
    for (unsigned i = 0; i < 256; ++i)
        if (frequencies[i] != 0)
            sparse_size += 1U + varint_size((uint32_t)frequencies[i]);
    uint8_t *payload = encode_huffman(tokens, token_length, frequencies, 0,
                                      &bits, &payload_length);
    uint64_t size = 21U + token_length;
    if (payload != NULL && 21U + sparse_size + payload_length < size)
        size = 21U + sparse_size + payload_length;
    if (payload != NULL && 21U + HUFFMAN_HEADER_BYTES + payload_length < size)
        size = 21U + HUFFMAN_HEADER_BYTES + payload_length;
    free(payload);
    free(tokens);
    return size;
}

int main(void) {
    enum { PART = 65536, LENGTH = 3 * PART };
    uint8_t *input = malloc(LENGTH);
    if (input == NULL) return 1;
    for (unsigned i = 0; i < 2U * PART; ++i) input[i] = next_byte();
    memcpy(input + 2U * PART, input, PART);
    for (unsigned i = 5; i < PART; i += 6) input[2U * PART + i] = next_byte();

    uint64_t short_size = lz_record_size(input, LENGTH, 32768U);
    uint64_t wide_size = lz_record_size(input, LENGTH, 1048576U);
    if (wide_size <= short_size) return 1;
    FILE *record = tmpfile();
    if (record == NULL) return 1;
    write_chunk_record(record, input, LENGTH);
    long actual_size = ftell(record);
    if (actual_size < 0 || (uint64_t)actual_size != short_size ||
        fseek(record, 4, SEEK_SET) != 0 || fgetc(record) != 6) return 1;
    if (fclose(record) != 0) return 1;
    free(input);
    return 0;
}
