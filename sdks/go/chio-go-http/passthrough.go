package arc

import (
	"context"
	"net/http"
)

type chioPassthroughContextKey struct{}

// GetChioPassthrough returns the explicit fail-open degraded-state marker, if
// one was attached to the request context by Chio middleware.
func GetChioPassthrough(r *http.Request) (*ChioPassthrough, bool) {
	value := r.Context().Value(chioPassthroughContextKey{})
	passthrough, ok := value.(*ChioPassthrough)
	return passthrough, ok
}

func withChioPassthrough(ctx context.Context, passthrough *ChioPassthrough) context.Context {
	return context.WithValue(ctx, chioPassthroughContextKey{}, passthrough)
}
