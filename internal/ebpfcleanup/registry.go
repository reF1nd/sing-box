package ebpfcleanup

import (
	"slices"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
)

// Entry keeps a retryable eBPF cleanup alive independently of the box or
// inbound whose lifecycle first attempted it.
type Entry struct {
	close func() error
}

func New(close func() error) *Entry {
	if close == nil {
		panic("nil eBPF cleanup")
	}
	return &Entry{close: close}
}

var retained struct {
	access  sync.Mutex
	entries []*Entry
}

func Retain(entry *Entry) {
	if entry == nil {
		return
	}
	retained.access.Lock()
	defer retained.access.Unlock()
	if !slices.Contains(retained.entries, entry) {
		retained.entries = append(retained.entries, entry)
	}
}

func Release(entry *Entry) {
	if entry == nil {
		return
	}
	retained.access.Lock()
	defer retained.access.Unlock()
	index := slices.Index(retained.entries, entry)
	if index >= 0 {
		retained.entries = slices.Delete(retained.entries, index, index+1)
	}
}

func Contains(entry *Entry) bool {
	if entry == nil {
		return false
	}
	retained.access.Lock()
	defer retained.access.Unlock()
	return slices.Contains(retained.entries, entry)
}

// Retry calls a snapshot without holding the registry lock. A successful
// callback releases its own entry as part of the owner's normal Close path.
func Retry() error {
	retained.access.Lock()
	entries := slices.Clone(retained.entries)
	retained.access.Unlock()
	var errors []error
	for _, entry := range entries {
		if err := entry.close(); err != nil {
			errors = append(errors, err)
		}
	}
	return E.Errors(errors...)
}
