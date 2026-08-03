package ebpf

import (
	"strings"
	"testing"
)

func TestDetectCgroup2Mount(t *testing.T) {
	mountInfo := strings.Join([]string{
		"31 22 0:27 /user.slice /sys/fs/cgroup/user rw - cgroup2 cgroup rw",
		"29 22 0:25 / /sys/fs/cgroup rw,nosuid,nodev - cgroup2 cgroup rw",
		"30 22 0:26 / /sys/fs/cgroup\040copy rw - cgroup2 cgroup rw",
	}, "\n")
	path, err := detectCgroup2Mount(strings.NewReader(mountInfo))
	if err != nil {
		t.Fatal(err)
	}
	if path != "/sys/fs/cgroup" {
		t.Fatalf("unexpected cgroup2 mount: %s", path)
	}
}

func TestDetectCgroup2MountMissing(t *testing.T) {
	_, err := detectCgroup2Mount(strings.NewReader("29 22 0:25 / /sys/fs/cgroup rw - cgroup cgroup rw\n"))
	if err == nil {
		t.Fatal("expected missing cgroup2 error")
	}
}
