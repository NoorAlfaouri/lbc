/* Exercise short and long Huffman codes, partial bytes and corrupted data. */
#define main lbc_program_main
#include "../lbc.c"
#undef main

int main(void) {
    uint64_t frequencies[256] = {0};
    frequencies[0] = 1;
    frequencies[1] = 1;
    size_t length = 2;
    for (unsigned i = 2; i < 22; ++i) {
        frequencies[i] = frequencies[i - 1] + frequencies[i - 2];
        length += (size_t)frequencies[i];
    }
    HuffNode nodes[511];
    HuffCodes codes = {{0}, {0}};
    int root;
    unsigned symbols;
    build_huffman_tree(frequencies, nodes, &root, &symbols);
    if (!assign_codes(nodes, root, 0, 0, &codes) || codes.length[0] <= 12) return 1;
    uint8_t *original = malloc(length);
    uint8_t *restored = malloc(length);
    if (original == NULL || restored == NULL) return 1;
    size_t pos = 0;
    for (unsigned i = 0; i < 22; ++i)
        for (uint64_t j = 0; j < frequencies[i]; ++j) original[pos++] = (uint8_t)i;
    uint64_t bits = 0;
    size_t payload_length = 0;
    uint8_t *packed = encode_huffman(original, length, frequencies, 0, &bits, &payload_length);
    if (packed == NULL || bits % 8 == 0 || !decode_huffman(packed, payload_length, bits, frequencies,
                                          restored, (uint32_t)length) ||
        memcmp(original, restored, length) != 0) return 1;
    if (decode_huffman(packed, payload_length - 1, bits, frequencies,
                       restored, (uint32_t)length)) return 1;
    packed[0] ^= 0x80;
    if (decode_huffman(packed, payload_length, bits, frequencies,
                       restored, (uint32_t)length)) return 1;
    free(packed);
    free(restored);
    free(original);
    return 0;
}
