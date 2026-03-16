CLANG ?= clang

.PHONY: bpf
bpf:
	$(CLANG) -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86 \
		-c bpf/mark_delegate.c -o bpf/mark_delegate.o
