//go:build linux

package process

import (
	"os"
	"slices"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
)

func TestFindProcessInfoByPID(t *testing.T) {
	processInfo, err := FindProcessInfoByPID(uint32(os.Getpid()), uint32(os.Getuid()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if processInfo.ProcessID != uint32(os.Getpid()) || processInfo.UserId != int32(os.Getuid()) {
		t.Fatalf("unexpected process identity: %+v", processInfo)
	}
	if len(processInfo.ProcessPaths) == 0 || processInfo.ProcessPaths[0] == "" {
		t.Fatal("missing process path")
	}
	if strings.HasSuffix(processInfo.ProcessPaths[0], " (deleted)") {
		t.Fatalf("unexpected deleted suffix in process path: %q", processInfo.ProcessPaths[0])
	}
}

func TestFilterProcessPaths(t *testing.T) {
	input := []string{
		"/system/bin/app_process",
		"/system/bin/app_process64",
		"/usr/bin/curl",
	}
	got := filterProcessPaths(input)
	if C.IsAndroid {
		want := []string{"/usr/bin/curl"}
		if !slices.Equal(got, want) {
			t.Fatalf("filterProcessPaths on Android = %v, want %v", got, want)
		}
		return
	}
	if !slices.Equal(got, input) {
		t.Fatalf("filterProcessPaths on Linux = %v, want %v", got, input)
	}
}
