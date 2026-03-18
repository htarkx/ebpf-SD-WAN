CLANG ?= clang

.PHONY: bpf bpf-dns

bpf:
	$(CLANG) -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86 \
		-c bpf/mark_delegate.c -o bpf/mark_delegate.o

bpf-dns:
	$(CLANG) -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86 \
		-c bpf/dns_hijack.c -o bpf/dns_hijack.o
