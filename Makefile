V ?= @
GIT=git
NUM := {1..3}
STACK=stack
package = nuuanu
stack = $(stack_yaml) stack
stack_yaml = STACK_YAML="stack.yaml"

build:
	$(V)$(STACK) build

build-dirty:
	$(V)$(STACK) build --ghc-options=-fforce-recomp $(package)

git-%:
	$(V)$(GIT) add .
	$(V)$(GIT) commit -m "$(@:git-%=%)"
	$(V)$(GIT) push -u origin main

git_log:
	$(V)$(GIT) log -p -$(NUM)

git_pretty:
	 $(v)$(GIT) log --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit

git_log_line:
	$(v)$(GIT) logline

git_short:
	$(V)$(GIT) log --graph --abbrev-commit --decorate --date=relative --all

git_tree:
	$(V)$(GIT) tree

git_stree:
	$(V)$(GIT) stree

git_vtree:
	$(V)$(GIT) vtree

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
