//go:build linux

package process

import (
	"os"
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
	if processInfo.ProcessPath == "" {
		t.Fatal("missing process path")
	}
	if strings.HasSuffix(processInfo.ProcessPath, " (deleted)") {
		t.Fatalf("unexpected deleted suffix in process path: %q", processInfo.ProcessPath)
	}
}

func TestFilterProcessPath(t *testing.T) {
	for _, tc := range []struct {
		input       string
		wantAndroid string
		wantLinux   string
	}{
		{input: "/system/bin/app_process", wantAndroid: "", wantLinux: "/system/bin/app_process"},
		{input: "/system/bin/app_process64", wantAndroid: "", wantLinux: "/system/bin/app_process64"},
		{input: "/usr/bin/curl", wantAndroid: "/usr/bin/curl", wantLinux: "/usr/bin/curl"},
	} {
		got := filterProcessPath(tc.input)
		want := tc.wantLinux
		if C.IsAndroid {
			want = tc.wantAndroid
		}
		if got != want {
			t.Fatalf("filterProcessPath(%q) = %q, want %q", tc.input, got, want)
		}
	}
}
