CC ?= cc
CFLAGS ?= -O3 -std=c11 -Wall -Wextra -Werror -pedantic -pthread
CPPFLAGS ?= -D_POSIX_C_SOURCE=200809L

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
INCLUDEDIR ?= $(PREFIX)/include

.PHONY: all test clean install uninstall
all: lbc

lbc: lbc.c
	TMPDIR="$(CURDIR)" $(CC) -pipe $(CPPFLAGS) $(CFLAGS) lbc.c -o lbc

test:
	@tmp=$$(mktemp); $(CC) $(CPPFLAGS) $(CFLAGS) -Wno-error=unused-function -DLBC_NO_MAIN lbc.c tests/test_lbc_api.c -o $$tmp && $$tmp; rc=$$?; rm -f $$tmp; exit $$rc
	./test_lbc.sh

install: lbc
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 lbc $(DESTDIR)$(BINDIR)/lbc
	install -d $(DESTDIR)$(INCLUDEDIR)
	install -m 644 lbc.h $(DESTDIR)$(INCLUDEDIR)/lbc.h

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/lbc
	rm -f $(DESTDIR)$(INCLUDEDIR)/lbc.h

deb: lbc
	rm -rf dist/deb
	mkdir -p dist/deb/usr/bin dist/deb/usr/include dist/deb/DEBIAN
	install -m 755 lbc dist/deb/usr/bin/lbc
	install -m 644 lbc.h dist/deb/usr/include/lbc.h
	echo "Package: lbc" > dist/deb/DEBIAN/control
	echo "Version: 1.0.0" >> dist/deb/DEBIAN/control
	echo "Section: utils" >> dist/deb/DEBIAN/control
	echo "Priority: optional" >> dist/deb/DEBIAN/control
	echo "Architecture: $$(dpkg --print-architecture 2>/dev/null || echo amd64)" >> dist/deb/DEBIAN/control
	echo "Maintainer: NoorAlfaouri <alfaouri1112@gmail.com>" >> dist/deb/DEBIAN/control
	echo "Description: LBC (Lossless Block Codec) - Ultra High-Ratio Compression Tool" >> dist/deb/DEBIAN/control
	echo " A standalone high-ratio C11 compressor featuring CMix context mixing." >> dist/deb/DEBIAN/control
	dpkg-deb --build dist/deb dist/lbc_1.0.0_$$(dpkg --print-architecture 2>/dev/null || echo amd64).deb
	rm -rf dist/deb

clean:
	rm -rf -- lbc build dist *.egg-info
