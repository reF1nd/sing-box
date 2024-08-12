package rule

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	"github.com/sagernet/sing/service/filemanager"
	"go4.org/netipx"
)

type abstractRuleSet struct {
	ctx         context.Context
	logger      logger.ContextLogger
	tag         string
	sType       string
	path        string
	format      string
	rules       []adapter.HeadlessRule
	ruleCount   uint64
	metadata    adapter.RuleSetMetadata
	lastUpdated time.Time
	refs        atomic.Int32
}

func (s *abstractRuleSet) Name() string {
	return s.tag
}

func (s *abstractRuleSet) Type() string {
	return s.sType
}

func (s *abstractRuleSet) Format() string {
	return s.format
}

func (s *abstractRuleSet) RuleCount() uint64 {
	return s.ruleCount
}

func (s *abstractRuleSet) UpdatedTime() time.Time {
	return s.lastUpdated
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
	return s.metadata
}

func (s *abstractRuleSet) ExtractIPSet() []*netipx.IPSet {
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

func (s *abstractRuleSet) loadFromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	content, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	err = s.loadBytes(content)
	if err != nil {
		return err
	}
	fs, _ := file.Stat()
	s.lastUpdated = fs.ModTime()
	return nil
}

func (s *abstractRuleSet) loadBytes(content []byte) error {
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
	return s.reloadRules(plainRuleSet.Rules)
}

func (s *abstractRuleSet) reloadRules(headlessRules []option.HeadlessRule) error {
	rules := make([]adapter.HeadlessRule, len(headlessRules))
	var ruleCount uint64
	for i, ruleOptions := range headlessRules {
		rule, err := NewHeadlessRule(s.ctx, ruleOptions)
		if err != nil {
			return E.Cause(err, "parse rule_set.rules.[", i, "]")
		}
		rules[i] = rule
		ruleCount += rule.RuleCount()
	}
	var metadata adapter.RuleSetMetadata
	metadata.ContainsProcessRule = HasHeadlessRule(headlessRules, isProcessHeadlessRule)
	metadata.ContainsWIFIRule = HasHeadlessRule(headlessRules, isWIFIHeadlessRule)
	metadata.ContainsIPCIDRRule = HasHeadlessRule(headlessRules, isIPCIDRHeadlessRule)
	s.rules = rules
	s.ruleCount = ruleCount
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
