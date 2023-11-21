//go:build with_script

package script

import (
	"context"
	"errors"
	"os"
	"os/exec"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	preStart                  string = "pre-start"
	preStartServicePreClose   string = "pre-start-service-pre-close"
	preStartServicePostClose  string = "pre-start-service-post-close"
	postStart                 string = "post-start"
	postStartServicePreClose  string = "post-start-service-pre-close"
	postStartServicePostClose string = "post-start-service-post-close"
	preClose                  string = "pre-close"
	postClose                 string = "post-close"
)

type Script struct {
	tag    string
	ctx    context.Context
	logger log.ContextLogger

	command        string
	args           []string
	directory      string
	env            []string
	stdoutLogLevel log.Level
	stderrLogLevel log.Level
	noFatal        bool
	mode           string

	cmd *exec.Cmd
}

func NewScript(ctx context.Context, logger log.ContextLogger, tag string, options option.ScriptOptions) (*Script, error) {
	s := &Script{
		tag:            tag,
		ctx:            ctx,
		logger:         logger,
		stdoutLogLevel: 0xff,
		stderrLogLevel: 0xff,
	}
	if options.Command == "" {
		return nil, E.New("missing command")
	}
	s.command = options.Command
	s.args = options.Args
	s.directory = options.Directory
	s.noFatal = options.NoFatal
	if options.Env != nil && len(options.Env) > 0 {
		s.env = make([]string, 0, len(options.Env))
		for k, v := range options.Env {
			s.env = append(s.env, k+"="+v)
		}
	}
	switch options.Mode {
	case preStart, preStartServicePreClose, preStartServicePostClose, postStart, postStartServicePreClose, postStartServicePostClose, preClose, postClose:
		s.mode = options.Mode
	case "":
		return nil, E.New("missing mode")
	default:
		return nil, E.New("invalid mode: ", options.Mode)
	}
	if options.LogOptions.Enabled {
		stdoutLogLevelStr := options.LogOptions.StdoutLogLevel
		if stdoutLogLevelStr == "" {
			stdoutLogLevelStr = "info"
		}
		stdoutLogLevel, err := log.ParseLevel(stdoutLogLevelStr)
		if err != nil {
			return nil, E.New("invalid stdout log level: ", stdoutLogLevelStr)
		}
		s.stdoutLogLevel = stdoutLogLevel
		stderrLogLevelStr := options.LogOptions.StderrLogLevel
		if stderrLogLevelStr == "" {
			stderrLogLevelStr = "error"
		}
		stderrLogLevel, err := log.ParseLevel(stderrLogLevelStr)
		if err != nil {
			return nil, E.New("invalid stderr log level: ", stderrLogLevelStr)
		}
		s.stderrLogLevel = stderrLogLevel
	}
	return s, nil
}

func (s *Script) Tag() string {
	return s.tag
}

func (s *Script) newCommand(ctx context.Context) *exec.Cmd {
	cmd := exec.CommandContext(ctx, s.command, s.args...)
	cmd.Env = os.Environ()
	if s.env != nil && len(s.env) > 0 {
		cmd.Env = append(cmd.Env, s.env...)
	}
	cmd.Dir = s.directory
	if s.stdoutLogLevel != 0xff {
		var f func(...any)
		switch s.stdoutLogLevel {
		case log.LevelPanic:
			f = s.logger.Panic
		case log.LevelFatal:
			f = s.logger.Fatal
		case log.LevelError:
			f = s.logger.Error
		case log.LevelWarn:
			f = s.logger.Warn
		case log.LevelInfo:
			f = s.logger.Info
		case log.LevelDebug:
			f = s.logger.Debug
		case log.LevelTrace:
			f = s.logger.Trace
		}
		if f != nil {
			cmd.Stdout = &logWriter{f: f}
		}
	}
	if s.stderrLogLevel != 0xff {
		var f func(...any)
		switch s.stdoutLogLevel {
		case log.LevelPanic:
			f = s.logger.Panic
		case log.LevelFatal:
			f = s.logger.Fatal
		case log.LevelError:
			f = s.logger.Error
		case log.LevelWarn:
			f = s.logger.Warn
		case log.LevelInfo:
			f = s.logger.Info
		case log.LevelDebug:
			f = s.logger.Debug
		case log.LevelTrace:
			f = s.logger.Trace
		}
		if f != nil {
			cmd.Stderr = &logWriter{f: f}
		}
	}
	return cmd
}

func (s *Script) PreStart() error {
	switch s.mode {
	case preStart:
		cmd := s.newCommand(s.ctx)
		s.logger.Info("executing pre-start script: ", cmd.String())
		err := cmd.Run()
		if err != nil {
			s.logger.Error("failed to execute pre-start script: ", cmd.String(), ", error: ", err)
			if !s.noFatal {
				return err
			}
		} else {
			s.logger.Info("pre-start script executed: ", cmd.String())
		}
	case preStartServicePreClose, preStartServicePostClose:
		cmd := s.newCommand(s.ctx)
		s.logger.Info("starting pre-start service script: ", cmd.String())
		err := cmd.Start()
		if err != nil {
			s.logger.Error("failed to start pre-start service script: ", cmd.String(), ", error: ", err)
			return err
		} else {
			s.logger.Info("pre-start service script started: ", cmd.String())
			s.cmd = cmd
			go func() {
				cmd := s.cmd
				err := cmd.Wait()
				if err != nil {
					if !s.noFatal {
						s.logger.Fatal("service script executed failed: ", cmd.String(), ", error: ", err)
					} else {
						s.logger.Error("service script executed failed: ", cmd.String(), ", error: ", err)
					}
				}
				s.cmd = nil
			}()
		}
	default:
	}
	return nil
}

func (s *Script) PostStart() error {
	switch s.mode {
	case postStart:
		cmd := s.newCommand(s.ctx)
		s.logger.Info("executing post-start script: ", cmd.String())
		err := cmd.Run()
		if err != nil {
			s.logger.Error("failed to execute post-start script: ", cmd.String(), ", error: ", err)
			if !s.noFatal {
				return err
			}
		} else {
			s.logger.Info("post-start script executed: ", cmd.String())
		}
	case postStartServicePreClose, postStartServicePostClose:
		cmd := s.newCommand(s.ctx)
		s.logger.Info("starting post-start service script: ", cmd.String())
		err := cmd.Start()
		if err != nil {
			s.logger.Error("failed to start post-start service script: ", cmd.String(), ", error: ", err)
			return err
		} else {
			s.logger.Info("post-start service script started: ", cmd.String())
			s.cmd = cmd
			go func() {
				cmd := s.cmd
				err := cmd.Wait()
				if err != nil && !errors.Is(err, context.Canceled) {
					if !s.noFatal {
						s.logger.Fatal("service script executed failed: ", cmd.String(), ", error: ", err)
					} else {
						s.logger.Error("service script executed failed: ", cmd.String(), ", error: ", err)
					}
				}
				s.cmd = nil
			}()
		}
	default:
	}
	return nil
}

func (s *Script) PreClose() error {
	switch s.mode {
	case preClose:
		cmd := s.newCommand(context.Background())
		s.logger.Info("executing pre-close script: ", cmd.String())
		err := cmd.Run()
		if err != nil {
			s.logger.Error("failed to execute pre-close script: ", cmd.String(), ", error: ", err)
			if !s.noFatal {
				return err
			}
		} else {
			s.logger.Info("pre-close script executed: ", cmd.String())
		}
	case preStartServicePreClose, postStartServicePreClose:
		cmd := s.cmd
		if cmd != nil {
			err := cmd.Cancel()
			if err != nil && !errors.Is(err, context.Canceled) {
				s.logger.Error("failed to cancel service script: ", cmd.String(), ", error: ", err)
				return err
			} else {
				s.logger.Info("service script canceled: ", cmd.String())
			}
		}
	default:
	}
	return nil
}

func (s *Script) PostClose() error {
	switch s.mode {
	case postClose:
		cmd := s.newCommand(context.Background())
		s.logger.Info("executing post-close script: ", cmd.String())
		err := cmd.Run()
		if err != nil {
			s.logger.Error("failed to execute post-close script: ", cmd.String(), ", error: ", err)
			if !s.noFatal {
				return err
			}
		} else {
			s.logger.Info("post-close script executed: ", cmd.String())
		}
	case preStartServicePostClose, postStartServicePostClose:
		cmd := s.cmd
		if cmd != nil {
			err := cmd.Cancel()
			if err != nil && !errors.Is(err, context.Canceled) {
				s.logger.Error("failed to cancel service script: ", cmd.String(), ", error: ", err)
				return err
			} else {
				s.logger.Info("service script canceled: ", cmd.String())
			}
		}
	default:
	}
	return nil
}
