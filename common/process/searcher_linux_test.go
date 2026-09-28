//go:build linux

package process

import (
	"os"
	"testing"
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
}
