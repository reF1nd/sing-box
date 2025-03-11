package constant

// Provider types.
const (
	ProviderTypeRemote = "remote"
	ProviderTypeLocal  = "local"
)

// ProviderDisplayName returns the display name of the provider type:
// HTTP, File, Compatible
func ProviderDisplayName(providerType string) string {
	switch providerType {
	case ProviderTypeRemote:
		return "HTTP"
	case ProviderTypeLocal:
		return "File"
	default:
		return "Compatible"
	}
}
