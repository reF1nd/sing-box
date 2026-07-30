BPF_CLANG ?= $(if $(strip $(ANDROID_NDK_HOME)),$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang,clang)
BPF_SYSTEM_INCLUDE ?= /usr/include
BPF_HOST_CC ?= cc
BPF_MULTIARCH ?= $(shell $(BPF_HOST_CC) -print-multiarch 2>/dev/null)
BPF_MULTIARCH_INCLUDE ?= $(BPF_SYSTEM_INCLUDE)/$(BPF_MULTIARCH)
BPF_CFLAGS ?= -target bpfel -O2 -g0
BPF_INCLUDE_FLAGS := -Inative -I$(BPF_SYSTEM_INCLUDE)
ifneq (,$(wildcard $(BPF_MULTIARCH_INCLUDE)))
BPF_INCLUDE_FLAGS += -I$(BPF_MULTIARCH_INCLUDE)
endif

SOURCE := native/shared_network.bpf.c
OBJECT := native/shared_network.bpf.o

.PHONY: generate check clean

generate:
	@set -eu; \
	temporary="$$(mktemp "$(OBJECT).XXXXXX")"; \
	trap 'rm -f "$$temporary"' EXIT; \
	$(BPF_CLANG) $(BPF_CFLAGS) $(BPF_INCLUDE_FLAGS) \
		-c "$(SOURCE)" -o "$$temporary"; \
	mv "$$temporary" "$(OBJECT)"

check:
	@set -eu; \
	temporary="$$(mktemp "$(OBJECT).XXXXXX")"; \
	trap 'rm -f "$$temporary"' EXIT; \
	$(BPF_CLANG) $(BPF_CFLAGS) $(BPF_INCLUDE_FLAGS) \
		-c "$(SOURCE)" -o "$$temporary"; \
	if ! cmp -s "$(OBJECT)" "$$temporary"; then \
		echo "$(OBJECT) is stale; run 'make generate' in this directory" >&2; \
		exit 1; \
	fi

clean:
	rm -f "$(OBJECT)"
