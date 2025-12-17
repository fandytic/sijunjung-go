package http

type contextKey string

// ContextUserIDKey is used to store the authenticated user id in the request context.
const ContextUserIDKey contextKey = "user_id"
