package interrupt

import "context"

type contextKeyIsExternalConnection struct{}

func ContextWithIsExternalConnection(ctx context.Context, isExternal bool) context.Context {
	return context.WithValue(ctx, contextKeyIsExternalConnection{}, isExternal)
}

func IsExternalConnectionFromContext(ctx context.Context) bool {
	isExternal, _ := ctx.Value(contextKeyIsExternalConnection{}).(bool)
	return isExternal
}

type contextKeyIsResourceDownload struct{}

// ContextWithIsResourceDownload protects service-managed configuration and UI downloads
// from outbound-group switching. Cancellation and deadlines are preserved.
func ContextWithIsResourceDownload(ctx context.Context, isResourceDownload bool) context.Context {
	return context.WithValue(ctx, contextKeyIsResourceDownload{}, isResourceDownload)
}

func IsResourceDownloadFromContext(ctx context.Context) bool {
	isResourceDownload, _ := ctx.Value(contextKeyIsResourceDownload{}).(bool)
	return isResourceDownload
}
