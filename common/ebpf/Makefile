ANDROID_NDK_HOME ?= /usr/share/android-ndk-r29
NDK_TOOLCHAIN := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64
BPF_CLANG ?= $(NDK_TOOLCHAIN)/bin/clang
BPF_STRIP ?= $(NDK_TOOLCHAIN)/bin/llvm-strip
BPF_OBJCOPY ?= $(NDK_TOOLCHAIN)/bin/llvm-objcopy
BPF_SYSROOT ?= $(NDK_TOOLCHAIN)/sysroot
BPF_RESOURCE_INCLUDE ?= $(shell $(BPF_CLANG) -print-resource-dir 2>/dev/null)/include
BPF_UAPI_ARCH_INCLUDE ?= $(BPF_SYSROOT)/usr/include/aarch64-linux-android
BPF_CFLAGS ?= -mcpu=v1 -O2 -g0 -ffreestanding -mllvm -disable-block-placement -mllvm -disable-branch-fold
BPF_INCLUDE_FLAGS := -nostdinc -Inative -isystem $(BPF_RESOURCE_INCLUDE) \
	-isystem $(BPF_SYSROOT)/usr/include -isystem $(BPF_UAPI_ARCH_INCLUDE)
GO_GENERATE_HOST_OS := $(shell go env GOHOSTOS)
GO_GENERATE_HOST_ARCH := $(shell go env GOHOSTARCH)

GENERATED_DIR := internal/bpfgen
GENERATED := $(addprefix $(GENERATED_DIR)/,cgroup_bpfel.go cgroup_bpfel.o cgroup_bpfeb.go cgroup_bpfeb.o \
	shared_network_bpfel.go shared_network_bpfel.o shared_network_bpfeb.go shared_network_bpfeb.o manifest.txt)
NATIVE_SOURCES := $(sort $(wildcard native/*.c native/*.h))

.PHONY: generate check clean

generate:
	@test -x "$(BPF_CLANG)" || { echo "Android NDK r29 Clang not found at $(BPF_CLANG)" >&2; exit 1; }
	@test -x "$(BPF_STRIP)" || { echo "Android NDK r29 llvm-strip not found at $(BPF_STRIP)" >&2; exit 1; }
	@test -x "$(BPF_OBJCOPY)" || { echo "Android NDK r29 llvm-objcopy not found at $(BPF_OBJCOPY)" >&2; exit 1; }
	@test -f "$(BPF_SYSROOT)/usr/include/linux/bpf.h" || { echo "Android NDK Linux UAPI headers not found under $(BPF_SYSROOT)" >&2; exit 1; }
	@test -f "$(BPF_UAPI_ARCH_INCLUDE)/asm/types.h" || { echo "Android NDK arm64 UAPI asm headers not found under $(BPF_UAPI_ARCH_INCLUDE)" >&2; exit 1; }
	@$(BPF_CLANG) --version | head -n 1 | grep -q 'clang version 21\.' || { echo "eBPF objects must be generated with NDK r29 Clang 21" >&2; exit 1; }
	@mkdir -p $(GENERATED_DIR)
	env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u OBJC_INCLUDE_PATH \
	BPF2GO_CC="$(BPF_CLANG)" \
	BPF2GO_STRIP="$(BPF_STRIP)" \
	BPF2GO_CFLAGS="$(BPF_CFLAGS) $(BPF_INCLUDE_FLAGS)" \
	GOOS="$(GO_GENERATE_HOST_OS)" GOARCH="$(GO_GENERATE_HOST_ARCH)" CGO_ENABLED=0 \
		go generate -tags with_ebpf generate.go
	@for object in $(GENERATED_DIR)/*_bpfel.o $(GENERATED_DIR)/*_bpfeb.o; do \
		$(BPF_OBJCOPY) --remove-section=.BTF --remove-section=.BTF.ext "$$object"; \
	done
	@{ \
		echo 'generator: Android NDK r29 Clang 21'; \
		echo 'targets: bpfel,bpfeb'; \
		echo 'cflags: $(BPF_CFLAGS) -nostdinc -Inative -isystem <clang-resource>/include -isystem <ndk-sysroot>/usr/include -isystem <ndk-sysroot>/usr/include/aarch64-linux-android'; \
		echo 'include_environment: cleared'; \
		echo "bpf2go: $$(go list -m -f {{.Version}} github.com/cilium/ebpf)"; \
		$(BPF_CLANG) --version | head -n 1 | sed 's/^/clang: /'; \
		sha256sum $(NATIVE_SOURCES) $(GENERATED_DIR)/*.o; \
	} > $(GENERATED_DIR)/manifest.txt

check:
	@temporary="$$(mktemp -d)"; \
	trap 'rm -rf "$$temporary"' EXIT; \
	mkdir -p "$$temporary/$(GENERATED_DIR)"; \
	cp $(GENERATED) "$$temporary/$(GENERATED_DIR)"; \
	$(MAKE) generate; \
	for file in $(GENERATED); do \
		cmp -s "$$file" "$$temporary/$$file" || { echo "$$file is stale; run 'make generate' in common/ebpf" >&2; exit 1; }; \
	done

clean:
	rm -f $(GENERATED)
