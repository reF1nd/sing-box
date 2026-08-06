package ebpf

import (
	"bufio"
	"io"
	"os"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

func DetectCgroup2Mount() (string, error) {
	mountInfo, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", E.Cause(err, "open process mount info")
	}
	defer mountInfo.Close()
	path, err := detectCgroup2Mount(mountInfo)
	if err != nil {
		return "", err
	}
	return path, nil
}

func detectCgroup2Mount(reader io.Reader) (string, error) {
	var (
		bestPath string
		bestRoot bool
	)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		separator := strings.Index(line, " - ")
		if separator < 0 {
			continue
		}
		leftFields := strings.Fields(line[:separator])
		rightFields := strings.Fields(line[separator+3:])
		if len(leftFields) < 5 || len(rightFields) == 0 || rightFields[0] != "cgroup2" {
			continue
		}
		root := unescapeMountInfoPath(leftFields[3]) == "/"
		path := unescapeMountInfoPath(leftFields[4])
		if bestPath == "" || root && !bestRoot || root == bestRoot && len(path) < len(bestPath) {
			bestPath = path
			bestRoot = root
		}
	}
	if err := scanner.Err(); err != nil {
		return "", E.Cause(err, "read process mount info")
	}
	if bestPath == "" {
		return "", E.New("cgroup2 is not mounted")
	}
	return bestPath, nil
}

func unescapeMountInfoPath(path string) string {
	return strings.NewReplacer(
		`\040`, " ",
		`\011`, "\t",
		`\012`, "\n",
		`\134`, `\`,
	).Replace(path)
}
