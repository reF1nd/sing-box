package rule

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/service/filemanager"
	"go4.org/netipx"
)

type abstractRuleSet struct {
	ctx         context.Context
	logger      logger.ContextLogger
	tag         string
	access      sync.RWMutex
	path        string
	format      string
	rules       []adapter.HeadlessRule
	metadata    adapter.RuleSetMetadata
	lastUpdated time.Time
	refs        atomic.Int32
}

func (s *abstractRuleSet) Name() string {
	return s.tag
}

func (s *abstractRuleSet) String() string {
	return strings.Join(F.MapToString(s.rules), " ")
}

func (s *abstractRuleSet) getPath(ctx context.Context, path string) (string, error) {
	if path == "" {
		path = s.tag
		switch s.format {
		case C.RuleSetFormatSource, "":
			path += ".json"
		case C.RuleSetFormatBinary:
			path += ".srs"
		}
	}
	path = filemanager.BasePath(ctx, path)
	path, _ = filepath.Abs(path)
	if rw.IsDir(path) {
		return "", E.New("rule_set path is a directory: ", path)
	}
	return path, nil
}

func (s *abstractRuleSet) Metadata() adapter.RuleSetMetadata {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.metadata
}

func (s *abstractRuleSet) ExtractIPSet() []*netipx.IPSet {
	s.access.RLock()
	defer s.access.RUnlock()
	return common.FlatMap(s.rules, extractIPSetFromRule)
}

func (s *abstractRuleSet) IncRef() {
	s.refs.Add(1)
}

func (s *abstractRuleSet) DecRef() {
	if s.refs.Add(-1) < 0 {
		panic("rule-set: negative refs")
	}
}

func (s *abstractRuleSet) Cleanup() {
	if s.refs.Load() == 0 {
		s.rules = nil
	}
}

func (s *abstractRuleSet) reloadRules(headlessRules []option.HeadlessRule) error {
	rules := make([]adapter.HeadlessRule, len(headlessRules))
	var err error
	for i, ruleOptions := range headlessRules {
		rules[i], err = NewHeadlessRule(s.ctx, ruleOptions)
		if err != nil {
			return E.Cause(err, "parse rule_set.rules.[", i, "]")
		}
	}
	var metadata adapter.RuleSetMetadata
	metadata.ContainsProcessRule = hasHeadlessRule(headlessRules, isProcessHeadlessRule)
	metadata.ContainsWIFIRule = hasHeadlessRule(headlessRules, isWIFIHeadlessRule)
	metadata.ContainsIPCIDRRule = hasHeadlessRule(headlessRules, isIPCIDRHeadlessRule)
	s.access.Lock()
	s.rules = rules
	s.metadata = metadata
	return nil
}

func (s *abstractRuleSet) Match(metadata *adapter.InboundContext) bool {
	for _, rule := range s.rules {
		if rule.Match(metadata) {
			return true
		}
	}
	return false
}
