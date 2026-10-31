#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ -e lbc-test-artifacts ] || [ -e lbc ]; then
    printf '%s\n' 'refusing to reuse existing test artifacts' >&2
    exit 1
fi
mkdir lbc-test-artifacts
trap 'rm -rf -- lbc-test-artifacts; rm -f -- lbc' EXIT
TMPDIR="$PWD/lbc-test-artifacts"
export TMPDIR
TMPDIR="$TMPDIR" cc -pipe -std=c11 -O3 -Wall -Wextra -Werror -pedantic -D_POSIX_C_SOURCE=200809L lbc.c -o lbc
cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic -D_POSIX_C_SOURCE=200809L tests/test_lz_copy.c -o lbc-test-artifacts/test-lz-copy
./lbc-test-artifacts/test-lz-copy
cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic -D_POSIX_C_SOURCE=200809L tests/test_lz_selection.c -o lbc-test-artifacts/test-lz-selection
./lbc-test-artifacts/test-lz-selection
cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic -D_POSIX_C_SOURCE=200809L tests/test_huffman.c -o lbc-test-artifacts/test-huffman
./lbc-test-artifacts/test-huffman

printf abc > lbc-test-artifacts/abc
[ "$(./lbc sha256 lbc-test-artifacts/abc)" = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ]

# Decode a real document archived by the previous release before using it as
# a stable compression fixture. This also covers legacy BWT mode 5.
./lbc decompress tests/fixtures/readme-v3.lbc lbc-test-artifacts/readme-original.md
[ "$(./lbc sha256 lbc-test-artifacts/readme-original.md)" = "56c83819f0e5b0f060de14ff739eb44088910d7d053f7ca24409a2722f5da580" ]
./lbc compress lbc-test-artifacts/readme-original.md lbc-test-artifacts/readme.lbc 32768
[ "$(wc -c < lbc-test-artifacts/readme.lbc)" -lt 4000 ]
./lbc decompress lbc-test-artifacts/readme.lbc lbc-test-artifacts/readme-restored.md
cmp lbc-test-artifacts/readme-original.md lbc-test-artifacts/readme-restored.md

# A noncanonical frequency varint in the v4 BWT table must be rejected.
cp lbc-test-artifacts/readme.lbc lbc-test-artifacts/bad-varint.lbc
printf '\200\000' | dd of=lbc-test-artifacts/bad-varint.lbc bs=1 seek=97 conv=notrunc status=none
if ./lbc decompress lbc-test-artifacts/bad-varint.lbc lbc-test-artifacts/bad-varint-output; then
    printf '%s\n' 'noncanonical frequency was accepted' >&2
    exit 1
fi
[ ! -e lbc-test-artifacts/bad-varint-output ]

# Exercise both the old sparse LZ table and the new compact LZ table.
./lbc decompress tests/fixtures/source-v3.lbc lbc-test-artifacts/legacy-source.c
[ "$(./lbc sha256 lbc-test-artifacts/legacy-source.c)" = "bb2f576ec02f4a2cd3702c0d145d253302d7ef133f1df6a1e3a638a3af548063" ]
./lbc compress lbc-test-artifacts/legacy-source.c lbc-test-artifacts/source-v4.lbc 65536
[ "$(od -An -tu1 -j73 -N1 lbc-test-artifacts/source-v4.lbc | tr -d ' ')" = 6 ]
[ "$(wc -c < lbc-test-artifacts/source-v4.lbc)" -lt 19084 ]
./lbc decompress lbc-test-artifacts/source-v4.lbc lbc-test-artifacts/source-restored.c
cmp lbc-test-artifacts/legacy-source.c lbc-test-artifacts/source-restored.c

# The repeated block is separated by more than 32 KiB and belongs to one chunk.
./lbc generate-bytes lbc-test-artifacts/distant-a 65536 813
./lbc generate-bytes lbc-test-artifacts/distant-b 65536 1291
cat lbc-test-artifacts/distant-a lbc-test-artifacts/distant-b lbc-test-artifacts/distant-a > lbc-test-artifacts/distant-input
./lbc compress lbc-test-artifacts/distant-input lbc-test-artifacts/distant.lbc 262144
[ "$(wc -c < lbc-test-artifacts/distant.lbc)" -lt 150000 ]
./lbc decompress lbc-test-artifacts/distant.lbc lbc-test-artifacts/distant-restored
cmp lbc-test-artifacts/distant-input lbc-test-artifacts/distant-restored

./lbc generate lbc-test-artifacts/repeated.txt 1 3 211
chunk_bytes=$(((1024 * 1024 + 2) / 3 * 4 + 5))
./lbc compress lbc-test-artifacts/repeated.txt lbc-test-artifacts/repeated.lbc "$chunk_bytes"
./lbc decompress lbc-test-artifacts/repeated.lbc lbc-test-artifacts/restored.txt
cmp lbc-test-artifacts/repeated.txt lbc-test-artifacts/restored.txt
[ "$(./lbc sha256 lbc-test-artifacts/repeated.txt)" = "$(./lbc sha256 lbc-test-artifacts/restored.txt)" ]

./lbc generate lbc-test-artifacts/legacy-huffman-source.txt 7 2 211
legacy_huffman_chunk=$((32 * 1024 * 1024))
[ "$(wc -c < lbc-test-artifacts/legacy-huffman-source.txt)" -gt "$((8 * 1024 * 1024))" ]
./lbc compress lbc-test-artifacts/legacy-huffman-source.txt lbc-test-artifacts/legacy-huffman.lbc "$legacy_huffman_chunk"
printf 'LBC1\001' | dd of=lbc-test-artifacts/legacy-huffman.lbc bs=1 seek=0 count=5 conv=notrunc status=none
./lbc decompress lbc-test-artifacts/legacy-huffman.lbc lbc-test-artifacts/legacy-huffman-restored.txt
cmp lbc-test-artifacts/legacy-huffman-source.txt lbc-test-artifacts/legacy-huffman-restored.txt
cp lbc-test-artifacts/legacy-huffman.lbc lbc-test-artifacts/v2-huffman.lbc
printf 'LBC2\002' | dd of=lbc-test-artifacts/v2-huffman.lbc bs=1 seek=0 count=5 conv=notrunc status=none
./lbc decompress lbc-test-artifacts/v2-huffman.lbc lbc-test-artifacts/v2-huffman-restored.txt
cmp lbc-test-artifacts/legacy-huffman-source.txt lbc-test-artifacts/v2-huffman-restored.txt

structured_bytes=0
i=0
while [ "$i" -lt 12000 ]; do
    printf 'static unsigned parse_header_token(unsigned char *cursor) { return (cursor[0] * 17u + cursor[1] * 31u + cursor[2]) & 255u; }\n' >> lbc-test-artifacts/structured.c
    i=$((i + 1))
done
structured_bytes=$(wc -c < lbc-test-artifacts/structured.c)
./lbc compress lbc-test-artifacts/structured.c lbc-test-artifacts/structured.lbc 4194304
structured_archive_bytes=$(wc -c < lbc-test-artifacts/structured.lbc)
[ "$structured_archive_bytes" -lt 248 ]
./lbc decompress lbc-test-artifacts/structured.lbc lbc-test-artifacts/structured-restored.c
cmp lbc-test-artifacts/structured.c lbc-test-artifacts/structured-restored.c

if [ -n "${LBC_TEST_SOURCE:-}" ]; then
    test -f "$LBC_TEST_SOURCE"
    test -n "${LBC_TEST_MAX_ARCHIVE_BYTES:-}"
    ./lbc compress "$LBC_TEST_SOURCE" lbc-test-artifacts/external-source.lbc 65536
    external_archive_bytes=$(wc -c < lbc-test-artifacts/external-source.lbc)
    [ "$external_archive_bytes" -lt "$LBC_TEST_MAX_ARCHIVE_BYTES" ]
    ./lbc decompress lbc-test-artifacts/external-source.lbc lbc-test-artifacts/external-restored
    cmp "$LBC_TEST_SOURCE" lbc-test-artifacts/external-restored
fi

i=0
while [ "$i" -lt 15000 ]; do
    printf '\377\000abc\n' >> lbc-test-artifacts/lz-binary.bin
    i=$((i + 1))
done
lz_binary_bytes=$(wc -c < lbc-test-artifacts/lz-binary.bin)
./lbc compress lbc-test-artifacts/lz-binary.bin lbc-test-artifacts/lz-binary.lbc
lz_binary_archive_bytes=$(wc -c < lbc-test-artifacts/lz-binary.lbc)
[ "$lz_binary_archive_bytes" -lt "$((lz_binary_bytes / 10))" ]
./lbc decompress lbc-test-artifacts/lz-binary.lbc lbc-test-artifacts/lz-binary-restored.bin
cmp lbc-test-artifacts/lz-binary.bin lbc-test-artifacts/lz-binary-restored.bin


./lbc generate-bytes lbc-test-artifacts/arbitrary.bin 262144 89
system_sha=$(sha256sum lbc-test-artifacts/arbitrary.bin)
system_sha=${system_sha%% *}
[ "$(./lbc sha256 lbc-test-artifacts/arbitrary.bin)" = "$system_sha" ]
./lbc compress lbc-test-artifacts/arbitrary.bin lbc-test-artifacts/arbitrary.lbc 65536
cp lbc-test-artifacts/arbitrary.lbc lbc-test-artifacts/legacy-v1.lbc
printf 'LBC1\001' | dd of=lbc-test-artifacts/legacy-v1.lbc bs=1 seek=0 count=5 conv=notrunc status=none
./lbc decompress lbc-test-artifacts/legacy-v1.lbc lbc-test-artifacts/legacy-restored.bin
cmp lbc-test-artifacts/arbitrary.bin lbc-test-artifacts/legacy-restored.bin

./lbc decompress lbc-test-artifacts/arbitrary.lbc lbc-test-artifacts/arbitrary-restored.bin
cmp lbc-test-artifacts/arbitrary.bin lbc-test-artifacts/arbitrary-restored.bin

./lbc generate-bytes lbc-test-artifacts/partial.bin 131073 987
./lbc compress lbc-test-artifacts/partial.bin lbc-test-artifacts/partial.lbc 65536
./lbc decompress lbc-test-artifacts/partial.lbc lbc-test-artifacts/partial-restored.bin
cmp lbc-test-artifacts/partial.bin lbc-test-artifacts/partial-restored.bin

: > lbc-test-artifacts/empty.bin
./lbc compress lbc-test-artifacts/empty.bin lbc-test-artifacts/empty.lbc
./lbc decompress lbc-test-artifacts/empty.lbc lbc-test-artifacts/empty-restored.bin
cmp lbc-test-artifacts/empty.bin lbc-test-artifacts/empty-restored.bin

cp lbc-test-artifacts/repeated.lbc lbc-test-artifacts/bad-digest.lbc
printf '\\000' | dd of=lbc-test-artifacts/bad-digest.lbc bs=1 seek=17 count=1 conv=notrunc status=none
if ./lbc decompress lbc-test-artifacts/bad-digest.lbc lbc-test-artifacts/rejected-digest.bin; then
    printf '%s\\n' 'corrupt SHA-256 digest was accepted' >&2
    exit 1
fi

cp lbc-test-artifacts/arbitrary.lbc lbc-test-artifacts/bad.lbc
printf NOPE | dd of=lbc-test-artifacts/bad.lbc bs=1 count=4 conv=notrunc status=none
if ./lbc decompress lbc-test-artifacts/bad.lbc lbc-test-artifacts/rejected.bin; then
    printf '%s\n' 'corrupt header was accepted' >&2
    exit 1
fi

printf '%s\n' 'all low-level compressor tests passed'
