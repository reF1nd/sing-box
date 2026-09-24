package rule

import (
	"slices"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

var _ RuleItem = (*ProcessPathItem)(nil)

type ProcessPathItem struct {
	processes  []string
	processMap map[string]bool
}

func NewProcessPathItem(processNameList []string) *ProcessPathItem {
	rule := &ProcessPathItem{
		processes:  processNameList,
		processMap: make(map[string]bool),
	}
	for _, processName := range processNameList {
		rule.processMap[processName] = true
	}
	return rule
}

func (r *ProcessPathItem) Match(metadata *adapter.InboundContext) bool {
	// Android also accepts package names here; that match needs no procfs scan.
	if C.IsAndroid && metadata.ProcessInfo != nil && slices.ContainsFunc(metadata.ProcessInfo.AndroidPackageNames, func(packageName string) bool { return r.processMap[packageName] }) {
		return true
	}
	processInfo := metadata.ResolveProcessInfo()
	if processInfo == nil {
		return false
	}
	if processInfo.ProcessPath != "" && r.processMap[processInfo.ProcessPath] {
		return true
	}
	if C.IsAndroid {
		return slices.ContainsFunc(processInfo.AndroidPackageNames, func(packageName string) bool { return r.processMap[packageName] })
	}
	return false
}

func (r *ProcessPathItem) String() string {
	var description string
	pLen := len(r.processes)
	if pLen == 1 {
		description = "process_path=" + r.processes[0]
	} else {
		description = "process_path=[" + strings.Join(r.processes, " ") + "]"
	}
	return description
}
