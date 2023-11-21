//go:build !with_script

package script

import (
	"context"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

type Script struct{}

func NewScript(_ context.Context, _ log.ContextLogger, _ string, _ option.ScriptOptions) (*Script, error) {
	return nil, E.New(`Script is not included in this build, rebuild with -tags with_script`)
}

func (s *Script) Tag() string {
	return ""
}

func (s *Script) PreStart() error {
	return E.New(`Script is not included in this build, rebuild with -tags with_script`)
}

func (s *Script) PostStart() error {
	return E.New(`Script is not included in this build, rebuild with -tags with_script`)
}

func (s *Script) PreClose() error {
	return E.New(`Script is not included in this build, rebuild with -tags with_script`)
}

func (s *Script) PostClose() error {
	return E.New(`Script is not included in this build, rebuild with -tags with_script`)
}
