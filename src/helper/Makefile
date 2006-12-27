INSTALL=install
PKGCONFIG=pkg-config

prefix=/usr/local
bindir=${prefix}/bin

APP_FLAG=-DAPP
MYCFLAGS=-g -W -Wall -pedantic -std=c99
OBJEXT=o

#Windows:
#LIBS=-lshlwapi
#EXEEXT=.exe

BINARY=obex-folder-listing$(EXEEXT) obex-capability$(EXEEXT)

.PHONY: all
all: $(BINARY)

ifneq ($(MAKECMDGOALS),clean)
include .dependencies
endif

.PHONY: depend
depend:
	$(CC) $(CFLAGS) -MM $(wildcard *.c) >.dependencies

.dependencies: $(wildcard *.c) $(wildcard *.h)
	$(CC) $(CFLAGS) -MM $(wildcard *.c) >$@

%.$(OBJEXT): %.c
	$(CC) $(MYCFLAGS) $(CFLAGS) $(APP_FLAG) -c -o $@ $<

%$(EXEEXT): %.$(OBJEXT)
	$(CC) $(MYCFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

.PHONY: %-create
%-create:
	$(INSTALL) -d $(DESTDIR)$*

.PHONY: %-install
%-bindir-install:
	$(INSTALL) -m 755 $* $(DESTDIR)$(bindir)

.PHONY: install
install: bindir-create $(patsubst %,%-bindir-install,$(BINARY))

.PHONY: clean
clean:
	rm -f $(BINARY) *.o *~ .dependencies
