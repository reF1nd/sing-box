package adapter

// ConfigChecker checks the configuration that Router.Reload would load.
//
// It is provided only by runners that reload on Router.Reload, such as
// `sing-box run`, so its presence also tells that reloading is supported.
type ConfigChecker interface {
	CheckConfig() error
}
