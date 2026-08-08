BPF_CLANG ?= $(if $(strip $(ANDROID_NDK_HOME)),$(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang,clang)
BPF_SYSTEM_INCLUDE ?= /usr/include
BPF_HOST_CC ?= cc
BPF_MULTIARCH ?= $(shell $(BPF_HOST_CC) -print-multiarch 2>/dev/null)
BPF_MULTIARCH_INCLUDE ?= $(BPF_SYSTEM_INCLUDE)/$(BPF_MULTIARCH)
BPF_CFLAGS ?= -target bpfel -mcpu=v1 -O2 -g0 -ffreestanding
BPF_INCLUDE_FLAGS := -Inative -I$(BPF_SYSTEM_INCLUDE)
ifneq (,$(wildcard $(BPF_MULTIARCH_INCLUDE)))
BPF_INCLUDE_FLAGS += -I$(BPF_MULTIARCH_INCLUDE)
endif

SHARED_NETWORK_SOURCE := native/shared_network.bpf.c
SHARED_NETWORK_OBJECT := native/shared_network.bpf.o
CGROUP_SOURCE := native/cgroup.bpf.c
CGROUP_OBJECT := native/cgroup.bpf.o
OBJECTS := $(SHARED_NETWORK_OBJECT) $(CGROUP_OBJECT)

.PHONY: generate check clean

generate:
	@set -eu; \
	for pair in "$(SHARED_NETWORK_SOURCE):$(SHARED_NETWORK_OBJECT)" "$(CGROUP_SOURCE):$(CGROUP_OBJECT)"; do \
		source="$${pair%%:*}"; object="$${pair#*:}"; \
		temporary="$$(mktemp "$$object.XXXXXX")"; \
		trap 'rm -f "$$temporary"' EXIT; \
		$(BPF_CLANG) $(BPF_CFLAGS) $(BPF_INCLUDE_FLAGS) -c "$$source" -o "$$temporary"; \
		mv "$$temporary" "$$object"; \
		trap - EXIT; \
	done

check:
	@set -eu; \
	for pair in "$(SHARED_NETWORK_SOURCE):$(SHARED_NETWORK_OBJECT)" "$(CGROUP_SOURCE):$(CGROUP_OBJECT)"; do \
		source="$${pair%%:*}"; object="$${pair#*:}"; \
		temporary="$$(mktemp "$$object.XXXXXX")"; \
		trap 'rm -f "$$temporary"' EXIT; \
		$(BPF_CLANG) $(BPF_CFLAGS) $(BPF_INCLUDE_FLAGS) -c "$$source" -o "$$temporary"; \
		if ! cmp -s "$$object" "$$temporary"; then \
			echo "$$object is stale; run 'make generate' in this directory" >&2; exit 1; \
		fi; \
		rm -f "$$temporary"; \
		trap - EXIT; \
	done

clean:
	rm -f $(OBJECTS)
