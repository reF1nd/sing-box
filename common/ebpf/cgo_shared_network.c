//go:build with_ebpf && (linux || android) && cgo

#include "native/shared_network_loader.c"
#include "native/shared_network_runtime.c"
