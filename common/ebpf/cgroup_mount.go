//go:build with_ebpf && (linux || android)

package ebpf

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// DetectProcessCgroup2Path returns the cgroup v2 directory containing the
// current process. Attaching there limits the self-bypass hook to this
// process' cgroup instead of changing the host-wide root cgroup.
func DetectProcessCgroup2Path() (string, error) {
	mount, err := detectCgroup2MountFromFile("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", E.Cause(err, "read process cgroup")
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 || fields[0] != "0" {
			continue
		}
		return resolveProcessCgroup2Path(mount, fields[2])
	}
	return "", E.New("process is not attached to a cgroup v2 hierarchy")
}

// DetectCgroup2Root returns the root of the cgroup v2 hierarchy visible to the
// current process. Programs attached here observe sockets from all descendant
// cgroups, not only sockets created by sing-box.
func DetectCgroup2Root() (string, error) {
	mount, err := detectCgroup2MountFromFile("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	return mount.path, nil
}

type cgroup2Mount struct {
	root string
	path string
}

func detectCgroup2MountFromFile(path string) (cgroup2Mount, error) {
	file, err := os.Open(path)
	if err != nil {
		return cgroup2Mount{}, E.Cause(err, "open process mount info")
	}
	defer file.Close()
	return detectCgroup2MountEntry(file)
}

func detectCgroup2Mount(reader io.Reader) (string, error) {
	mount, err := detectCgroup2MountEntry(reader)
	return mount.path, err
}

func detectCgroup2MountEntry(reader io.Reader) (cgroup2Mount, error) {
	var best cgroup2Mount
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		before, after, ok := strings.Cut(scanner.Text(), " - ")
		if !ok {
			continue
		}
		leftFields := strings.Fields(before)
		rightFields := strings.Fields(after)
		if len(leftFields) < 5 || len(rightFields) == 0 || rightFields[0] != "cgroup2" {
			continue
		}
		root := unescapeMountInfoPath(leftFields[3])
		path := unescapeMountInfoPath(leftFields[4])
		if best.path == "" || root == "/" && best.root != "/" || root == best.root && len(path) < len(best.path) {
			best = cgroup2Mount{root: root, path: path}
		}
	}
	if err := scanner.Err(); err != nil {
		return cgroup2Mount{}, E.Cause(err, "read process mount info")
	}
	if best.path == "" {
		return cgroup2Mount{}, E.New("cgroup2 is not mounted")
	}
	return best, nil
}

func resolveProcessCgroup2Path(mount cgroup2Mount, processPath string) (string, error) {
	processPath = filepath.Clean(filepath.FromSlash(processPath))
	mountRoot := filepath.Clean(filepath.FromSlash(mount.root))
	if mountRoot != "/" {
		if processPath != mountRoot && !strings.HasPrefix(processPath, mountRoot+string(filepath.Separator)) {
			return "", E.New("process cgroup is outside the visible cgroup2 mount")
		}
		processPath = strings.TrimPrefix(processPath, mountRoot)
	}
	relative := strings.TrimPrefix(processPath, string(filepath.Separator))
	if relative == "" {
		return mount.path, nil
	}
	return filepath.Join(mount.path, relative), nil
}

func unescapeMountInfoPath(path string) string {
	return strings.NewReplacer(
		`\040`, " ",
		`\011`, "\t",
		`\012`, "\n",
		`\134`, `\`,
	).Replace(path)
}
