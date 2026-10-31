# LBC2: standalone C lossless block codec

LBC2 is an independently implemented C11 codec for text, source-like data, and arbitrary bytes. Compression, decompression, SHA-256, block indexing, LZ tokenization, BWT, move-to-front, and Huffman coding are implemented in `lbc.c`; it does not call or link a ready-made compression or hash library. The executable uses only the C/POSIX runtime for memory and file handling.

**It is not claimed to be a globally novel compression algorithm.** Its format and implementation are original to this project, while its building blocks (block deduplication, LZ77-style matches, Huffman coding, and adaptive method choice) are established techniques. In particular, LZ plus Huffman is a well-known family of designs. Proving that no one has used the exact combination before would require a literature/patent search and still cannot be guaranteed here.

No lossless codec can shrink every input by 80%: incompressible data may stay the same size or grow slightly. Ratios and speed are workload-specific; benchmark results below are evidence only for the stated deterministic fixtures, not natural or arbitrary source code.

## LBC2 design

1. Split input into fixed-size chunks (8 MiB by default; callers may choose another size); hash each with in-source FNV-1a and compare bytes on hash matches before deduplicating. Consecutive duplicate chunk IDs are run-length encoded.
2. For each unique chunk, estimate complete record sizes for raw bytes, static Huffman, greedy LZ77 tokens (raw, full-table Huffman, or sparse-table Huffman), and—when the chunk is at most 32 KiB—BWT followed by move-to-front, zero-run coding, and sparse-table Huffman. Select the smallest candidate, including its side information.
3. The LZ matcher tries a 32 KiB backward window and, for larger chunks, a 1 MiB window. It compares the full encoded sizes and keeps the smaller result, because a wider greedy search can otherwise increase the archive size. Each search uses matches of at least 5 bytes and a bounded 64-candidate hash chain, and is enabled for chunks no larger than 8 MiB. Trying both windows increases encoding work. The BWT transform sorts cyclic shifts by prefix doubling; BWT/MTF are optional candidates, not universal wins.
4. Store original byte length and a SHA-256 digest in the frame. The decoder reconstructs the output, checks its size and digest, then publishes it.

The Huffman decoder uses a 12-bit prefix lookup, falling back to the tree for longer codes and short final bit sequences. It still validates the exact bit count and all decoded symbol frequencies.

The version-4 `LBC2` frame keeps deterministic big-endian fixed-width fields. Methods 6 and 7 encode the sparse frequency tables of LZ and BWT blocks using unsigned base-128 variable-length integers; the decoder rejects zero, overflowing, and noncanonical frequencies. Method 8 provides an adaptive integer Range Coder with Order-0 and Order-1 multi-context statistical models using Fenwick binary indexed trees ($O(\log_2 256)$ time complexity per symbol). Method 9 (LBC-BitLZ) integrates an advanced context-adaptive binary Range Coder over LZ77 with four repeat match distances (`rep0`, `rep1`, `rep2`, `rep3`), a 12-state Markov token transition model, short-rep matches, and distance slot aligned bit trees. Method 10 (LBC-CMix) introduces a maximum-ratio bitwise Context Mixing engine with dual-rate counters (fast shift-2 and slow count-adaptive counters), 16 multi-scale context models (Orders 1-8, previous-word + token, line indentation/column, dynamic stride autocorrelation model, indirect context, and symmetric match model), paired with linear perceptron mixers and triple Adaptive Probability Maps (APM) running entirely on fixed-point integer arithmetic (zero floating-point, zero `-lm` link dependency), plus a reversible bijective x86 branch normalization filter. Methods 0–5 retain their earlier meanings. The decoder reads LBC2 versions 2, 3, and 4 and legacy LBC1 version 1. Older decoder binaries do not understand version 4 and must be updated before reading newly produced archives.

The implementation limits files to 600 MiB and blocks to 1,000,000. Output paths must not already exist. Temporary files are created beside the output and cleaned on success/error. The large benchmark's scratch files are confined to the project directory.

## Public C API

`lbc.h` defines a linkable C API contract for buffer and file operations, implemented in `lbc.c` and validated by `tests/test_lbc_api.c` as part of `make test`.

The public contract returns `lbc_status` values (`LBC_OK`, `LBC_ERROR_ARGUMENT`, `LBC_ERROR_LIMIT`, `LBC_ERROR_FORMAT`, `LBC_ERROR_IO`, `LBC_ERROR_MEMORY`, `LBC_ERROR_EXISTS`, `LBC_ERROR_UNSUPPORTED`, `LBC_ERROR_INTERNAL`), and never prints diagnostics or invokes `exit()` in the host process. Memory buffers allocated by `lbc_compress()` and `lbc_decompress()` are owned by the caller and released with `lbc_free()`. File-based APIs (`lbc_compress_file()`, `lbc_decompress_file()`) reject existing destination paths. Operations are reentrant and enforce buffer/block limits (600 MiB maximum stream length, 1,000,000 block count limit).

The decoder is heavily optimized for throughput:
- 64-bit register-backed bit reservoir with 32-bit chunk refills and 12-bit primary prefix lookup table.
- Fast literal runs using `memchr` hardware search and bulk `memcpy`.
- Fast RLE runs using single-instruction `memset`.
- Unaligned 128-bit/16-byte chunk copying for wide match distances.
- Single-byte fast-path varint decoding.

## Installation on Any Device

### Option 1: Via Python `pip` (Recommended for any device)
```sh
pip install git+https://github.com/NoorAlfaouri/lbc.git
```
Provides the `lbc` terminal command and the `import lbc` Python library.

### Option 2: One-Line Installer (Linux / macOS / BSD)
```sh
curl -fsSL https://raw.githubusercontent.com/NoorAlfaouri/lbc/master/install.sh | bash
```

### Option 3: Compile from Source (C11)
```sh
git clone https://github.com/NoorAlfaouri/lbc.git
cd lbc
make
sudo make install
```

## Build and test

Requirements: C11 compiler, POSIX file APIs, and basic command-line utilities. Third-party compression/hash libraries are not needed. Optional comparison commands are detected by the benchmark script.

```sh
make
make test

# Compress (creates file.lbc automatically; level -9 ultra is default):
./lbc source.c
./lbc c source.c
./lbc -9 source.c
./lbc -1 source.c               # Fast compression preset

# Decompress (restores original name by stripping .lbc; restores permissions & timestamp):
./lbc archive.lbc
./lbc d archive.lbc
./lbc -d archive.lbc -o output.txt

# Test archive integrity (validates SHA-256 in memory without writing to disk):
./lbc -t archive.lbc

# Overwrite existing destination file:
./lbc -f source.c

# Inspect archive metadata:
./lbc i archive.lbc
```

The test script checks a SHA-256 known-answer vector and cross-checks SHA-256 with `sha256sum`. It exercises exact roundtrips of repeated shell text, repeated source-like lines, NUL/0xff-containing binary data, deterministic arbitrary data, partial and empty files; checks version-3 LZ and BWT archive fixtures plus older frames; and rejects malformed headers, a noncanonical frequency, and a corrupted digest. The source-like fixture compresses 1,500,000 repeated bytes to 204 bytes (99.9864% reduction) with a 4 MiB chunk; Zstandard `-3` compressed the same fixture to 248 bytes in the reproducible benchmark. The binary fixture compresses 90,000 repeated bytes to 103 bytes (99.8856%). These deliberately repetitive fixtures are not representative natural code. To test an existing real file without adding it to the repository, set `LBC_TEST_SOURCE=/path/to/file` and `LBC_TEST_MAX_ARCHIVE_BYTES=N` for `make test`; the test compares the restored bytes with that file.

### License

MIT License. Open source and free for commercial and private use.
