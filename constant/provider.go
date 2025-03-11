package constant

// Provider types.
const (
	ProviderTypeInline = "inline"
	ProviderTypeLocal  = "local"
	ProviderTypeRemote = "remote"
)

// ProviderDisplayName returns the display name of the provider type:
// HTTP, File, Compatible
func ProviderDisplayName(providerType string) string {
	switch providerType {
	case ProviderTypeInline:
		return "Inline"
	case ProviderTypeLocal:
		return "File"
	case ProviderTypeRemote:
		return "HTTP"
	default:
		return "Compatible"
	}
}
