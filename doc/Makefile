INSTALL=install
XMLTO=xmlto

prefix=/usr/local
mandir=${prefix}/share/man

BINARY=obexpushd
MANSECT=1

.PHONY: all
all: man

.PHONY: man
man: $(BINARY).$(MANSECT)
%.1: %.xml
	$(XMLTO) man $^

.PHONY: html
html: $(BINARY).html
%.html: %.xml
	$(XMLTO) xhtml-nochunks $^

.PHONY: install
install:
	$(INSTALL) -d $(DESTDIR)$(mandir)/man$(MANSECT)
	$(INSTALL) -m 644 $(BINARY).$(MANSECT) $(DESTDIR)$(mandir)/man$(MANSECT)

.PHONY: clean
clean:
	rm -f *.$(MANSECT) *.html *~
