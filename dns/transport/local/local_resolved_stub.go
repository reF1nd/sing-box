//go:build !linux

//nolint:unused
package local

import (
	"context"
	"os"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

func isSystemdResolvedManaged() bool {
	return false
}

func NewResolvedResolver(ctx context.Context, logger logger.ContextLogger) (ResolvedResolver, error) {
	return nil, os.ErrInvalid
}

func checkResolvedFallback(_ context.Context, _ []M.Socksaddr) error {
	return nil
}
