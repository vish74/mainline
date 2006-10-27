INSTALL=install
PKGCONFIG=pkg-config

prefix=/usr/local
bindir=${prefix}/bin

MYCFLAGS=-g -W -Wall -pedantic -std=c99

obexpushd_CFLAGS=$(shell $(PKGCONFIG) --cflags openobex bluez)
obexpushd_LIBS=$(shell $(PKGCONFIG) --libs openobex bluez)
obexpushd_OBJECTS=obexpush-sdp.o obexpushd.o obex_auth.o md5.o utf.o

BINARY=obexpushd

.PHONY: all
all: $(BINARY) $(MANPAGE)

ifneq ($(MAKECMDGOALS),clean)
include .dependencies
endif

.PHONY: depend
depend:
	$(CC) $(CFLAGS) -MM $(SOURCES) >.dependencies

SOURCES=$(wildcard *.c)
HEADERS=$(wildcard *.h)
.dependencies: $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -MM $(SOURCES) >$@

%.o: %.c
	$(CC) $(MYCFLAGS) $(CFLAGS) -c -o $@ $<

obexpushd: $(obexpushd_OBJECTS)
	$(CC) $(MYCFLAGS) $(obexpushd_CFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS) $(obexpushd_LIBS)

.PHONY: install
install:
	$(INSTALL) -d $(DESTDIR)$(bindir)
	$(INSTALL) -m 755 $(BINARY) $(DESTDIR)$(bindir)

.PHONY: clean
clean:
	rm -f $(BINARY) *.o *~ .dependencies
