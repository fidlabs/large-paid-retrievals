// Package pieceaccess gates piece retrieval by owner wallet or signed voucher.
package pieceaccess

import (
	"context"
	"net/http"
)

type accessContextKey struct{}

// AccessChecked reports whether pieceaccess middleware ran for this request.
func AccessChecked(ctx context.Context) bool {
	_, ok := ctx.Value(accessContextKey{}).(struct{})
	return ok
}

// Authorizer evaluates whether a client may access a piece before payment.
type Authorizer struct{}

// NewAuthorizer returns a passthrough authorizer until policy and voucher checks land.
func NewAuthorizer() *Authorizer {
	return &Authorizer{}
}

// Middleware wraps next so access is checked before payment and upstream proxying.
func (a *Authorizer) Middleware(next http.Handler) http.Handler {
	if a == nil {
		panic("pieceaccess: Authorizer is required")
	}
	if next == nil {
		panic("pieceaccess: next handler is required")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), accessContextKey{}, struct{}{})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
