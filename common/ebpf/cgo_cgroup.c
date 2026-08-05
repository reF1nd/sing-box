//go:build with_ebpf && (linux || android) && cgo

#include "native/cgroup.c"

// Native cgroup program builders are compiled through this translation unit.
