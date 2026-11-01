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

clean:
	rm -rf -- lbc build dist *.egg-info
