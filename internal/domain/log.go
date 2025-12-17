package domain

import "context"

// AppLogger abstracts logging to stdout and persistence layers.
type AppLogger interface {
	Info(ctx context.Context, msg string)
	Error(ctx context.Context, msg string)
}
