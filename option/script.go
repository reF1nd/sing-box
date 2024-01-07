package option

type ScriptOptions struct {
	Mode           string            `json:"mode"`
	Command        string            `json:"command"`
	Args           Listable[string]  `json:"args,omitempty"`
	Env            map[string]string `json:"env,omitempty"`
	Dir            string            `json:"dir,omitempty"`
	IgnoreFailures bool              `json:"ignore_failures,omitempty"`
	StdoutLogLevel string            `json:"stdout_log_level,omitempty"`
	StderrLogLevel string            `json:"stderr_log_level,omitempty"`
}
