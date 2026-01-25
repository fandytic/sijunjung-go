package email

import (
	"context"
	"fmt"

	"github.com/example/sijunjung-go/internal/domain"
	mailjet "github.com/mailjet/mailjet-apiv3-go/v4"
)

// MailjetService implements domain.EmailService using Mailjet API.
type MailjetService struct {
	client   *mailjet.Client
	fromName string
	from     string
}

// NewMailjetService creates a new Mailjet email service.
func NewMailjetService(apiKey, secretKey, fromName, from string) *MailjetService {
	client := mailjet.NewMailjetClient(apiKey, secretKey)
	return &MailjetService{
		client:   client,
		fromName: fromName,
		from:     from,
	}
}

// SendOTP sends an OTP code to the specified email address.
func (s *MailjetService) SendOTP(ctx context.Context, email, code string) error {
	subject := "Verification Code - Sijunjung Go"
	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
</head>
<body style="font-family: Arial, sans-serif; padding: 20px;">
    <h2>Verification Code</h2>
    <p>Please use the following code to verify your email address:</p>
    <div style="background-color: #f4f4f4; padding: 20px; text-align: center; margin: 20px 0;">
        <h1 style="letter-spacing: 10px; color: #333;">%s</h1>
    </div>
    <p>This code will expire in 5 minutes.</p>
    <p>If you didn't request this code, please ignore this email.</p>
    <br>
    <p>Best regards,<br>Sijunjung Go Team</p>
</body>
</html>
`, code)

	textBody := fmt.Sprintf("Your verification code is: %s\n\nThis code will expire in 5 minutes.\n\nIf you didn't request this code, please ignore this email.\n\nBest regards,\nSijunjung Go Team", code)

	return s.send(email, subject, htmlBody, textBody)
}

// SendNewPassword sends a new password to the specified email address.
func (s *MailjetService) SendNewPassword(ctx context.Context, email, password string) error {
	subject := "Password Reset - Sijunjung Go"
	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
</head>
<body style="font-family: Arial, sans-serif; padding: 20px;">
    <h2>Password Reset</h2>
    <p>Your password has been reset. Here is your new password:</p>
    <div style="background-color: #f4f4f4; padding: 20px; text-align: center; margin: 20px 0;">
        <h1 style="letter-spacing: 5px; color: #333;">%s</h1>
    </div>
    <p style="color: #e74c3c;"><strong>Important:</strong> Please change your password after logging in for security purposes.</p>
    <p>If you didn't request this password reset, please contact our support immediately.</p>
    <br>
    <p>Best regards,<br>Sijunjung Go Team</p>
</body>
</html>
`, password)

	textBody := fmt.Sprintf("Your new password is: %s\n\nImportant: Please change your password after logging in for security purposes.\n\nIf you didn't request this password reset, please contact our support immediately.\n\nBest regards,\nSijunjung Go Team", password)

	return s.send(email, subject, htmlBody, textBody)
}

func (s *MailjetService) send(to, subject, htmlBody, textBody string) error {
	messagesInfo := []mailjet.InfoMessagesV31{
		{
			From: &mailjet.RecipientV31{
				Email: s.from,
				Name:  s.fromName,
			},
			To: &mailjet.RecipientsV31{
				{
					Email: to,
				},
			},
			Subject:  subject,
			TextPart: textBody,
			HTMLPart: htmlBody,
		},
	}

	messages := mailjet.MessagesV31{Info: messagesInfo}
	_, err := s.client.SendMailV31(&messages)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

var _ domain.EmailService = (*MailjetService)(nil)
