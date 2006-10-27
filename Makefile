
.PHONY: all
all: src-all doc-all

src-%:
	@$(MAKE) -C src $*

doc-%:
	@$(MAKE) -C doc $*

.PHONY: install
install: src-install doc-install

.PHONY: clean
clean: src-clean doc-clean
