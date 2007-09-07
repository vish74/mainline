all: build-all

build-%: build/CMakeCache.txt
	cd build && $(MAKE) $*

install: build-install

clean: build-clean

distclean: build
	rm -rf build

build/CMakeCache.txt:
	./configure

.PHONY: all install clean distclean
