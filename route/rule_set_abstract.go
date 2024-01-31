package route

import (
	"bytes"
	"context"
	"os"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/service/filemanager"
)

type abstractRuleSet struct {
	ctx         context.Context
	cancel      context.CancelFunc
	tag         string
	path        string
	pType       string
	format      string
	ruleCount   int
	metadata    adapter.RuleSetMetadata
	rules       []adapter.HeadlessRule
	updatedTime time.Time
}

func (s *abstractRuleSet) Tag() string {
	return s.tag
}

func (s *abstractRuleSet) Type() string {
	return s.pType
}

func (s *abstractRuleSet) Format() string {
	return s.format
}

func (s *abstractRuleSet) UpdatedTime() time.Time {
	return s.updatedTime
}

func (s *abstractRuleSet) RuleCount() int {
	return s.ruleCount
}

func (s *abstractRuleSet) Match(metadata *adapter.InboundContext) bool {
	for _, rule := range s.rules {
		if rule.Match(metadata) {
			return true
		}
	}
	return false
}

func (s *abstractRuleSet) Metadata() adapter.RuleSetMetadata {
	return s.metadata
}

func (s *abstractRuleSet) setPath() error {
	path := s.path
	if path == "" {
		path = s.tag
		switch s.format {
		case C.RuleSetFormatSource, "":
			path += ".json"
		case C.RuleSetFormatBinary:
			path += ".srs"
		}
		if foundPath, loaded := C.FindPath(path); loaded {
			path = foundPath
		}
	}
	if stat, err := os.Stat(path); err == nil {
		if stat.IsDir() {
			return E.New("rule_set path is a directory: ", path)
		}
		if stat.Size() == 0 {
			os.Remove(path)
		}
	}
	if !rw.FileExists(path) {
		path = filemanager.BasePath(s.ctx, path)
	}
	s.path = path
	return nil
}

func (s *abstractRuleSet) loadFromFile(router adapter.Router, firstLoad bool) error {
	if firstLoad {
		err := s.setPath()
		if err != nil {
			return err
		}
	}
	setFile, err := os.Open(s.path)
	if err != nil {
		return nil
	}
	fs, _ := setFile.Stat()
	modTime := fs.ModTime()
	if !firstLoad && modTime == s.updatedTime {
		return nil
	}
	content, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	err = s.loadData(router, content)
	if err != nil {
		return err
	}
	s.updatedTime = modTime
	return nil
}

func (s *abstractRuleSet) loadData(router adapter.Router, content []byte) error {
	var (
		err          error
		plainRuleSet option.PlainRuleSet
	)
	switch s.format {
	case C.RuleSetFormatSource, "":
		var compat option.PlainRuleSetCompat
		compat, err := json.UnmarshalExtended[option.PlainRuleSetCompat](content)
		if err != nil {
			return err
		}
		plainRuleSet = compat.Upgrade()
	case C.RuleSetFormatBinary:
		plainRuleSet, err = srs.Read(bytes.NewReader(content), false)
		if err != nil {
			return err
		}
	}
	var ruleCount int
	rules := make([]adapter.HeadlessRule, len(plainRuleSet.Rules))
	for i, ruleOptions := range plainRuleSet.Rules {
		rule, err := NewHeadlessRule(router, ruleOptions)
		if err != nil {
			return E.Cause(err, "parse rule_set.rules.[", i, "]")
		}
		rules[i] = rule
		ruleCount += rule.RuleCount()
	}
	s.metadata.ContainsProcessRule = hasHeadlessRule(plainRuleSet.Rules, isProcessHeadlessRule)
	s.metadata.ContainsWIFIRule = hasHeadlessRule(plainRuleSet.Rules, isWIFIHeadlessRule)
	s.ruleCount = ruleCount
	s.rules = rules
	return nil
}
