//go:build with_ebpf && (linux || android) && cgo

#include "native/cgroup.c"

// Native cgroup runtime is compiled through this translation unit.
