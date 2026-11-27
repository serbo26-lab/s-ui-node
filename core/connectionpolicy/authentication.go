package connectionpolicy

import "context"

type managedAuthenticationKey struct{}

// WithManagedAuthentication marks cores whose user lists come from panel
// clients. Removing the last enabled client must not enable anonymous access.
func WithManagedAuthentication(ctx context.Context) context.Context {
	return context.WithValue(ctx, managedAuthenticationKey{}, true)
}

func managedAuthentication(ctx context.Context) bool {
	managed, _ := ctx.Value(managedAuthenticationKey{}).(bool)
	return managed
}
