package rule

import (
	"bytes"
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"

	"go4.org/netipx"
)

var emptyRuleSetContent ruleSetContent

type abstractRuleSet struct {
	ctx         context.Context
	logger      logger.ContextLogger
	tag         string
	access      sync.Mutex
	path        string
	format      string
	content     atomic.Pointer[ruleSetContent]
	lastUpdated time.Time
	callbacks   list.List[adapter.RuleSetUpdateCallback]
	refs        atomic.Int32
}

func (s *abstractRuleSet) Name() string {
	return s.tag
}

func (s *abstractRuleSet) String() string {
	return s.loadContent().String()
}

func (s *abstractRuleSet) Metadata() adapter.RuleSetMetadata {
	return s.loadContent().metadata
}

func (s *abstractRuleSet) ExtractIPSet() []*netipx.IPSet {
	return common.FlatMap(s.loadContent().rules, extractIPSetFromRule)
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
		s.clearContent()
	}
}

func (s *abstractRuleSet) clearContent() {
	s.content.Store(nil)
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
	prepared, err := s.prepareBytes(content)
	if err != nil {
		return err
	}
	s.publishContent(prepared, ruleset)
	return nil
}

func (s *abstractRuleSet) prepareBytes(content []byte) (*ruleSetContent, error) {
	var (
		ruleSet option.PlainRuleSetCompat
		err     error
	)
	switch s.format {
	case C.RuleSetFormatSource, "":
		ruleSet, err = json.UnmarshalExtended[option.PlainRuleSetCompat](content)
		if err != nil {
			return nil, err
		}
	case C.RuleSetFormatBinary:
		ruleSet, err = srs.Read(bytes.NewReader(content), false)
		if err != nil {
			return nil, err
		}
	default:
		return nil, E.New("unknown rule-set format: ", s.format)
	}
	return s.prepareRuleSet(ruleSet)
}

func (s *abstractRuleSet) loadReader(reader io.Reader, ruleset adapter.RuleSet) error {
	var (
		ruleSet option.PlainRuleSetCompat
		err     error
	)
	switch s.format {
	case C.RuleSetFormatSource, "":
		content, err := io.ReadAll(reader)
		if err != nil {
			return err
		}
		ruleSet, err = json.UnmarshalExtended[option.PlainRuleSetCompat](content)
		if err != nil {
			return err
		}
	case C.RuleSetFormatBinary:
		ruleSet, err = srs.Read(reader, false)
		if err != nil {
			return err
		}
	default:
		return E.New("unknown rule-set format: ", s.format)
	}
	return s.loadRuleSet(ruleSet, ruleset)
}

func (s *abstractRuleSet) loadRuleSet(ruleSet option.PlainRuleSetCompat, ruleset adapter.RuleSet) error {
	prepared, err := s.prepareRuleSet(ruleSet)
	if err != nil {
		return err
	}
	s.publishContent(prepared, ruleset)
	return nil
}

func (s *abstractRuleSet) prepareRuleSet(ruleSet option.PlainRuleSetCompat) (*ruleSetContent, error) {
	ruleSet, err := mmapRuleSet(s.ctx, s.logger, s.tag, ruleSet)
	if err != nil {
		return nil, err
	}
	plainRuleSet, err := ruleSet.Upgrade()
	if err != nil {
		return nil, err
	}
	return s.prepareRules(plainRuleSet.Rules)
}

func (s *abstractRuleSet) reloadRules(headlessRules []option.HeadlessRule, ruleSet adapter.RuleSet) error {
	prepared, err := s.prepareRules(headlessRules)
	if err != nil {
		return err
	}
	s.publishContent(prepared, ruleSet)
	return nil
}

func (s *abstractRuleSet) prepareRules(headlessRules []option.HeadlessRule) (*ruleSetContent, error) {
	rules := make([]adapter.HeadlessRule, len(headlessRules))
	var err error
	for i, ruleOptions := range headlessRules {
		rules[i], err = NewHeadlessRule(s.ctx, ruleOptions)
		if err != nil {
			return nil, E.Cause(err, "parse rule_set.rules.[", i, "]")
		}
	}
	metadata := buildRuleSetMetadata(headlessRules)
	err = validateRuleSetMetadataUpdate(s.ctx, s.tag, metadata)
	if err != nil {
		return nil, err
	}
	return &ruleSetContent{rules: rules, metadata: metadata}, nil
}

func (s *abstractRuleSet) publishContent(content *ruleSetContent, ruleSet adapter.RuleSet) {
	s.access.Lock()
	s.content.Store(content)
	callbacks := s.callbacks.Array()
	s.access.Unlock()
	for _, callback := range callbacks {
		callback(ruleSet)
	}
}

func (s *abstractRuleSet) Match(metadata *adapter.InboundContext) bool {
	return s.loadContent().Match(metadata)
}

func (s *abstractRuleSet) loadContent() *ruleSetContent {
	content := s.content.Load()
	if content == nil {
		return &emptyRuleSetContent
	}
	return content
}
