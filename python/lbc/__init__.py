"""
LBC (Lossless Block Codec)
Ultra High-Ratio Lossless Compression Engine
"""

import sys
from ._clbc import compress, decompress, compress_file, decompress_file, cli

__version__ = "1.0.0"
__all__ = ["compress", "decompress", "compress_file", "decompress_file", "cli", "main"]

def main():
    sys.exit(cli(sys.argv))
