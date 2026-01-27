package domain

import "context"

// WhatsAppService defines behavior for sending WhatsApp messages.
type WhatsAppService interface {
	SendOTP(ctx context.Context, phone, code string) error
}
