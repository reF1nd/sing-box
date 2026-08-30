//go:build with_ebpf && (linux || android)

package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target bpfel,bpfeb -tags with_ebpf -go-package bpfgen -output-dir internal/bpfgen -output-stem tc TC native/tc.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target bpfel,bpfeb -tags with_ebpf -go-package bpfgen -output-dir internal/bpfgen -output-stem cgroup Cgroup native/cgroup.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target bpfel,bpfeb -tags with_ebpf -go-package bpfgen -output-dir internal/bpfgen -output-stem cgroup_coarse CgroupCoarse native/cgroup_coarse.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target bpfel,bpfeb -tags with_ebpf -go-package bpfgen -output-dir internal/bpfgen -output-stem cgroup_storage CgroupStorage native/cgroup_storage.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target bpfel,bpfeb -tags with_ebpf -go-package bpfgen -output-dir internal/bpfgen -output-stem shared_network SharedNetwork native/shared_network.bpf.c
