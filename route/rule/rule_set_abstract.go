package rule

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/common/x/list"
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
	callbacks   list.List[adapter.RuleSetUpdateCallback]
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

func (s *abstractRuleSet) RegisterCallback(callback adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	s.access.Lock()
	defer s.access.Unlock()
	return s.callbacks.PushBack(callback)
}

func (s *abstractRuleSet) UnregisterCallback(element *list.Element[adapter.RuleSetUpdateCallback]) {
	s.access.Lock()
	defer s.access.Unlock()
	s.callbacks.Remove(element)
}

func (s *abstractRuleSet) loadBytes(content []byte, ruleset adapter.RuleSet) error {
	var (
		ruleSet option.PlainRuleSetCompat
		err     error
	)
	switch s.format {
	case C.RuleSetFormatSource:
		ruleSet, err = json.UnmarshalExtended[option.PlainRuleSetCompat](content)
		if err != nil {
			return err
		}
	case C.RuleSetFormatBinary:
		ruleSet, err = srs.Read(bytes.NewReader(content), false)
		if err != nil {
			return err
		}
	default:
		return E.New("unknown rule-set format: ", s.format)
	}
	plainRuleSet, err := ruleSet.Upgrade()
	if err != nil {
		return err
	}
	return s.reloadRules(plainRuleSet.Rules, ruleset)
}

func (s *abstractRuleSet) reloadRules(headlessRules []option.HeadlessRule, ruleSet adapter.RuleSet) error {
	rules := make([]adapter.HeadlessRule, len(headlessRules))
	var err error
	for i, ruleOptions := range headlessRules {
		rules[i], err = NewHeadlessRule(s.ctx, ruleOptions)
		if err != nil {
			return E.Cause(err, "parse rule_set.rules.[", i, "]")
		}
	}
	var metadata adapter.RuleSetMetadata
	metadata.ContainsProcessRule = HasHeadlessRule(headlessRules, isProcessHeadlessRule)
	metadata.ContainsWIFIRule = HasHeadlessRule(headlessRules, isWIFIHeadlessRule)
	metadata.ContainsIPCIDRRule = HasHeadlessRule(headlessRules, isIPCIDRHeadlessRule)
	s.access.Lock()
	s.rules = rules
	s.metadata = metadata
	callbacks := s.callbacks.Array()
	s.access.Unlock()
	for _, callback := range callbacks {
		callback(ruleSet)
	}
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
