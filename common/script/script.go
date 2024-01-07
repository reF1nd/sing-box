package script

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	ServiceMode     = "service"
	StartScriptMode = "start"
	CloseScriptMode = "close"
)

type Script struct {
	ctx             context.Context
	logger          log.ContextLogger
	mode            string
	command         string
	args            []string
	dir             string
	optionEnvMap    map[string]string
	envMap          map[string]string
	ignoreFailures  bool
	stdoutLogWriter io.Writer
	stderrLogWriter io.Writer
	cmd             *exec.Cmd
}

func New(ctx context.Context, logger log.ContextLogger, options option.ScriptOptions) (*Script, error) {
	s := &Script{
		ctx:            ctx,
		logger:         logger,
		command:        options.Command,
		args:           options.Args,
		dir:            options.Dir,
		optionEnvMap:   options.Env,
		ignoreFailures: options.IgnoreFailures,
	}
	if s.command == "" {
		return nil, E.New("missing script command")
	}
	switch options.Mode {
	case ServiceMode, StartScriptMode, CloseScriptMode:
		s.mode = options.Mode
	case "":
		return nil, E.New("missing script mode")
	default:
		return nil, E.New("invalid script mode: ", options.Mode)
	}
	var err error
	s.stdoutLogWriter, err = parseLogLevelToLogWriter(logger, options.StdoutLogLevel, "stdout")
	if err != nil {
		return nil, E.Cause(err, "invalid script stdout log level")
	}
	s.stderrLogWriter, err = parseLogLevelToLogWriter(logger, options.StderrLogLevel, "stderr")
	if err != nil {
		return nil, E.Cause(err, "invalid script stderr log level")
	}
	return s, nil
}

func (s *Script) SetEnv(key, value string) {
	if s.envMap == nil {
		s.envMap = make(map[string]string)
	}
	s.envMap[key] = value
}

func (s *Script) newCommand(ctx context.Context) *exec.Cmd {
	cmd := exec.CommandContext(ctx, s.command, s.args...)
	cmd.Dir = s.dir
	envMap := make(map[string]string)
	if s.optionEnvMap != nil {
		for k, v := range s.optionEnvMap {
			envMap[k] = v
		}
	}
	if s.envMap != nil {
		for k, v := range s.envMap {
			envMap[k] = v
		}
	}
	envs := make([]string, 0, len(envMap))
	for k, v := range envMap {
		envs = append(envs, k+"="+v)
	}
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, envs...)
	cmd.Stdout = s.stdoutLogWriter
	cmd.Stderr = s.stderrLogWriter
	return cmd
}

func (s *Script) Start() error {
	switch s.mode {
	case ServiceMode:
		cmd := s.newCommand(s.ctx)
		s.cmd = cmd
		err := cmd.Start()
		if err != nil {
			if !s.ignoreFailures {
				return E.Cause(err, "service start failed: ", cmd.String())
			}
		}
		if !s.ignoreFailures {
			go func() {
				err := s.cmd.Wait()
				if err != nil {
					if strings.Contains(err.Error(), "signal") {
						return
					}
					if strings.Contains(err.Error(), "cancelled") {
						return
					}
					s.logger.Fatal("service run failed: ", err)
				}
			}()
		}
	case StartScriptMode:
		cmd := s.newCommand(s.ctx)
		err := cmd.Run()
		if err != nil {
			if !s.ignoreFailures {
				return E.Cause(err, "start script run failed: ", cmd.String())
			}
		}
	case CloseScriptMode:
	default:
		panic("unreachable")
	}
	return nil
}

func (s *Script) Close() error {
	switch s.mode {
	case ServiceMode:
		s.cmd.Cancel()
	case StartScriptMode:
	case CloseScriptMode:
		cmd := s.newCommand(context.Background())
		err := cmd.Run()
		if err != nil {
			if !s.ignoreFailures {
				return E.Cause(err, "close script run failed: ", cmd.String())
			}
		}
	default:
		panic("unreachable")
	}
	return nil
}

func parseLogLevelToLogWriter(logger log.ContextLogger, logLevel string, prefix string) (io.Writer, error) {
	if logLevel == "" {
		return io.Discard, nil
	}
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		return nil, err
	}
	var logFunc func(...any)
	switch level {
	case log.LevelTrace:
		logFunc = logger.Trace
	case log.LevelDebug:
		logFunc = logger.Debug
	case log.LevelInfo:
		logFunc = logger.Info
	case log.LevelWarn:
		logFunc = logger.Warn
	case log.LevelError:
		logFunc = logger.Error
	case log.LevelFatal:
		logFunc = logger.Fatal
	case log.LevelPanic:
		logFunc = logger.Panic
	default:
		logFunc = func(_ ...any) {}
	}
	return &logWriter{prefix: prefix, logFunc: logFunc}, nil
}
