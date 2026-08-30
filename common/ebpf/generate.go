//go:build with_ebpf && (linux || android)

package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target bpfel,bpfeb -tags with_ebpf -go-package bpfgen -output-dir internal/bpfgen -output-stem tc TC native/tc.bpf.c
