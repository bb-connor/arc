package arc

import (
	"context"
	"net/http"
)

type arcPassthroughContextKey struct{}

// GetArcPassthrough returns the explicit fail-open degraded-state marker, if
// one was attached to the request context by ARC middleware.
func GetArcPassthrough(r *http.Request) (*ArcPassthrough, bool) {
	value := r.Context().Value(arcPassthroughContextKey{})
	passthrough, ok := value.(*ArcPassthrough)
	return passthrough, ok
}

func withArcPassthrough(ctx context.Context, passthrough *ArcPassthrough) context.Context {
	return context.WithValue(ctx, arcPassthroughContextKey{}, passthrough)
}
