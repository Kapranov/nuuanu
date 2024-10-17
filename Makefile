V ?= @
STACK=stack
package = nuuanu
stack_yaml = STACK_YAML="stack.yaml"
stack = $(stack_yaml) stack

build:
	$(V)$(STACK) build

build-dirty:
	$(V)$(STACK) build --ghc-options=-fforce-recomp $(package)

run:
	$(V)$(STACK) build --fast && $(STACK) exec -- $(package)

install:
	$(V)$(STACK) install

ghci:
	$(V)$(STACK)ghci

test:
	$(V)$(STACK) test

test-ghci:
	$(V)$(STACK) ghci $(package):test:$(package)-tests

bench:
	$(V)$(STACK) bench $(package)

ghcid:
	$(V)$(STACK) exec -- ghcid -c "stack ghci $(package) --test --ghci-options='-fobject-code -fno-warn-unused-do-bind'"

dev-deps:
	$(V)$(STACK) install ghcid

.PHONY : build build-dirty run install ghci test test-ghci ghcid dev-deps
