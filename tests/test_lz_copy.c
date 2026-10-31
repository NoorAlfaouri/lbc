/* Exercise LZ decoder overlap semantics with independently specified tokens. */
#define main lbc_program_main
#include "../lbc.c"
#undef main

int main(void) {
    const uint8_t single[] = {'x', 0xff, 1, 127, 1};
    const uint8_t periodic[] = {'a', 'b', 'c', 0xff, 1, 0x80, 2, 3};
    const uint8_t disjoint[] = {'a', 'b', 'c', 'd', 'e', 0xff, 1, 5, 5};
    const uint8_t invalid[] = {'x', 0xff, 1, 5, 2};
    uint8_t output[259];
    if (!decode_lz_tokens(single, sizeof(single), output, 128)) return 1;
    for (unsigned i = 0; i < 128; ++i) if (output[i] != 'x') return 1;
    if (!decode_lz_tokens(periodic, sizeof(periodic), output, sizeof(output))) return 1;
    for (unsigned i = 0; i < sizeof(output); ++i)
        if (output[i] != (uint8_t)"abc"[i % 3]) return 1;
    if (!decode_lz_tokens(disjoint, sizeof(disjoint), output, 10) ||
        memcmp(output, "abcdeabcde", 10) != 0) return 1;
    if (decode_lz_tokens(invalid, sizeof(invalid), output, 6)) return 1;
    return 0;
}
