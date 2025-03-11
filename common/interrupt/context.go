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

type contextKeyIsProviderConnection struct{}

func ContextWithIsProviderConnection(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKeyIsProviderConnection{}, true)
}

func IsProviderConnectionFromContext(ctx context.Context) bool {
	return ctx.Value(contextKeyIsProviderConnection{}) != nil
}
