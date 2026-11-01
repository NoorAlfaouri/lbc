from setuptools import setup, Extension

clbc = Extension(
    "lbc._clbc",
    sources=["py_lbc.c", "lbc.c"],
    include_dirs=["."],
    extra_compile_args=["-O3", "-std=c11", "-D_POSIX_C_SOURCE=200809L", "-DLBC_CLI_NAME=lbc_cli_main", "-pthread"],
)

setup(
    name="lbc-codec",
    version="1.0.0",
    description="LBC (Lossless Block Codec) - Ultra High-Ratio Compression Engine",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="NoorAlfaouri",
    author_email="alfaouri1112@gmail.com",
    license="MIT",
    packages=["lbc"],
    package_dir={"": "python"},
    ext_modules=[clbc],
    entry_points={
        "console_scripts": [
            "lbc=lbc:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: C",
        "Programming Language :: Python :: 3",
        "Topic :: System :: Archiving :: Compression",
    ],
    python_requires=">=3.7",
)
