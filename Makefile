all: build-all

build-%: build
	cd build && $(MAKE) $*

install: build-install

clean: build-clean

distclean: build
	rm -rf build

build:
	./configure

.PHONY: all install clean distclean
