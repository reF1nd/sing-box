package interrupt

import "context"

type contextKeyIsExternalConnection struct{}

func ContextWithIsExternalConnection(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKeyIsExternalConnection{}, true)
}

func IsExternalConnectionFromContext(ctx context.Context) bool {
	return ctx.Value(contextKeyIsExternalConnection{}) != nil
}

type contextKeyIsResourceDownload struct{}

// ContextWithIsResourceDownload protects service-managed configuration and UI downloads
// from outbound-group switching. Cancellation and deadlines are preserved.
func ContextWithIsResourceDownload(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKeyIsResourceDownload{}, true)
}

func IsResourceDownloadFromContext(ctx context.Context) bool {
	return ctx.Value(contextKeyIsResourceDownload{}) != nil
}
