package rule

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"

	"github.com/sagernet/fswatch"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service/filemanager"
)

var _ adapter.RuleSet = (*LocalRuleSet)(nil)

type LocalRuleSet struct {
	abstractRuleSet
	watcher   *fswatch.Watcher
	callbacks list.List[adapter.RuleSetUpdateCallback]
}

func NewLocalRuleSet(ctx context.Context, logger logger.ContextLogger, options option.RuleSet) (*LocalRuleSet, error) {
	ruleSet := &LocalRuleSet{
		abstractRuleSet: abstractRuleSet{
			ctx:    ctx,
			logger: logger,
			tag:    options.Tag,
			sType:  options.Type,
			format: options.Format,
		},
	}
	if options.Type == C.RuleSetTypeInline {
		if len(options.InlineOptions.Rules) == 0 {
			return nil, E.New("empty inline rule-set")
		}
		err := ruleSet.reloadRules(options.InlineOptions.Rules)
		if err != nil {
			return nil, err
		}
	} else {
		path, err := ruleSet.getPath(ctx, options.Path)
		if err != nil {
			return nil, err
		}
		ruleSet.path = path
		err = ruleSet.reloadFile(path)
		if err != nil {
			return nil, err
		}
		watcher, err := fswatch.NewWatcher(fswatch.Options{
			Path: []string{path},
			Callback: func(path string) {
				uErr := ruleSet.reloadFile(path)
				if uErr != nil {
					logger.ErrorContext(log.ContextWithNewID(context.Background()), E.Cause(uErr, "reload rule-set ", options.Tag))
				}
			},
		})
		if err != nil {
			return nil, err
		}
		ruleSet.watcher = watcher
	}
	return ruleSet, nil
}

func (s *LocalRuleSet) StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error {
	if s.watcher != nil {
		err := s.watcher.Start()
		if err != nil {
			s.logger.Error(E.Cause(err, "watch rule-set file"))
		}
	}
	return nil
}

func (s *LocalRuleSet) reloadFile(path string) error {
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

func (s *LocalRuleSet) loadBytes(content []byte) error {
	var (
		ruleSet option.PlainRuleSetCompat
		err     error
	)
	switch s.format {
	case C.RuleSetFormatSource, "":
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

func (s *LocalRuleSet) reloadRules(headlessRules []option.HeadlessRule) error {
	err := s.abstractRuleSet.reloadRules(headlessRules)
	if err != nil {
		return err
	}
	callbacks := s.callbacks.Array()
	s.access.Unlock()
	for _, callback := range callbacks {
		callback(s)
	}
	return nil
}

func (s *LocalRuleSet) getPath(ctx context.Context, path string) (string, error) {
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

func (s *LocalRuleSet) PostStart() error {
	return nil
}

func (s *LocalRuleSet) RegisterCallback(callback adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	s.access.Lock()
	defer s.access.Unlock()
	return s.callbacks.PushBack(callback)
}

func (s *LocalRuleSet) UnregisterCallback(element *list.Element[adapter.RuleSetUpdateCallback]) {
	s.access.Lock()
	defer s.access.Unlock()
	s.callbacks.Remove(element)
}

func (s *LocalRuleSet) Update(ctx context.Context) error {
	return nil
}

func (s *LocalRuleSet) Close() error {
	s.rules = nil
	return common.Close(common.PtrOrNil(s.watcher))
}
