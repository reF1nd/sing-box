//go:build darwin || linux

package libbox

import (
	"os"
	"runtime"
	"runtime/debug"
)

func RedirectStderr(path string) error {
	if stats, err := os.Stat(path); err == nil && stats.Size() > 0 {
		_ = os.Rename(path, path+".old")
	}
	outputFile, err := os.Create(path)
	if err != nil {
		return err
	}
	if runtime.GOOS != "android" {
		err = outputFile.Chown(sUserID, sGroupID)
		if err != nil {
			outputFile.Close()
			os.Remove(outputFile.Name())
			return err
		}
	}
	err = debug.SetCrashOutput(outputFile, debug.CrashOptions{})
	if err != nil {
		outputFile.Close()
		os.Remove(outputFile.Name())
		return err
	}
	return outputFile.Close()
}
