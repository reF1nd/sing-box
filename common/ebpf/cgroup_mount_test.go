//go:build with_ebpf && (linux || android)

package ebpf

import (
	"strings"
	"testing"
)

func TestDetectCgroup2Mount(t *testing.T) {
	mountInfo := strings.NewReader("23 1 0:22 / /sys/fs/cgroup rw,relatime - cgroup2 cgroup rw\n")
	if path, err := detectCgroup2Mount(mountInfo); err != nil || path != "/sys/fs/cgroup" {
		t.Fatalf("detect cgroup2 mount: path=%q err=%v", path, err)
	}
}

func TestDetectCgroup2MountPrefersRoot(t *testing.T) {
	mountInfo := strings.NewReader(
		"23 1 0:22 /nested /sys/fs/cgroup/nested rw - cgroup2 cgroup rw\n" +
			"24 1 0:22 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n",
	)
	if path, err := detectCgroup2Mount(mountInfo); err != nil || path != "/sys/fs/cgroup" {
		t.Fatalf("detect root cgroup2 mount: path=%q err=%v", path, err)
	}
}

func TestDetectCgroup2MountUsesVisibleHierarchyRoot(t *testing.T) {
	mountInfo := strings.NewReader("23 1 0:22 /apps /sys/fs/cgroup rw - cgroup2 cgroup rw\n")
	mount, err := detectCgroup2MountEntry(mountInfo)
	if err != nil {
		t.Fatal(err)
	}
	if mount.root != "/apps" || mount.path != "/sys/fs/cgroup" {
		t.Fatalf("unexpected visible cgroup root: %+v", mount)
	}
}

func TestResolveProcessCgroup2Path(t *testing.T) {
	for _, testCase := range []struct {
		mount       cgroup2Mount
		processPath string
		expected    string
	}{
		{cgroup2Mount{"/", "/sys/fs/cgroup"}, "/system.slice/sing-box", "/sys/fs/cgroup/system.slice/sing-box"},
		{cgroup2Mount{"/apps", "/sys/fs/cgroup"}, "/apps/sing-box", "/sys/fs/cgroup/sing-box"},
		{cgroup2Mount{"/apps/sing-box", "/sys/fs/cgroup"}, "/apps/sing-box", "/sys/fs/cgroup"},
	} {
		actual, err := resolveProcessCgroup2Path(testCase.mount, testCase.processPath)
		if err != nil || actual != testCase.expected {
			t.Fatalf("resolve process cgroup: path=%q err=%v, want %q", actual, err, testCase.expected)
		}
	}
}
