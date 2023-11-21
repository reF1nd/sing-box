package option

type ScriptOptions struct {
	Tag        string            `json:"tag"`
	Command    string            `json:"command"`
	Args       Listable[string]  `json:"args,omitempty"`
	Directory  string            `json:"directory,omitempty"`
	Mode       string            `json:"mode"`
	Env        map[string]string `json:"env,omitempty"`
	NoFatal    bool              `json:"no_fatal,omitempty"`
	LogOptions ScriptLogOptions  `json:"log,omitempty"`
}

type ScriptLogOptions struct {
	Enabled        bool   `json:"enabled"`
	StdoutLogLevel string `json:"stdout_log_level,omitempty"`
	StderrLogLevel string `json:"stderr_log_level,omitempty"`
}
