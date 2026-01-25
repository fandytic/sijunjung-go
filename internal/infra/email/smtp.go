package email

import (
	"context"
	"fmt"
	"net/smtp"

	"github.com/example/sijunjung-go/internal/domain"
)

// SMTPService implements domain.EmailService using SMTP.
type SMTPService struct {
	host string
	port string
	user string
	pass string
	from string
}

// NewSMTPService creates a new SMTP email service.
func NewSMTPService(host, port, user, pass, from string) *SMTPService {
	return &SMTPService{
		host: host,
		port: port,
		user: user,
		pass: pass,
		from: from,
	}
}

// SendOTP sends an OTP code to the specified email address.
func (s *SMTPService) SendOTP(ctx context.Context, email, code string) error {
	subject := "Verification Code - Sijunjung Go"
	body := fmt.Sprintf(`
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

	msg := fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"\r\n"+
		"%s", s.from, email, subject, body)

	addr := fmt.Sprintf("%s:%s", s.host, s.port)

	// If no credentials provided, send without auth (for local testing)
	if s.user == "" || s.pass == "" {
		return smtp.SendMail(addr, nil, s.from, []string{email}, []byte(msg))
	}

	auth := smtp.PlainAuth("", s.user, s.pass, s.host)
	return smtp.SendMail(addr, auth, s.from, []string{email}, []byte(msg))
}

// SendNewPassword sends a new password to the specified email address.
func (s *SMTPService) SendNewPassword(ctx context.Context, email, password string) error {
	subject := "Password Reset - Sijunjung Go"
	body := fmt.Sprintf(`
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

	msg := fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"\r\n"+
		"%s", s.from, email, subject, body)

	addr := fmt.Sprintf("%s:%s", s.host, s.port)

	if s.user == "" || s.pass == "" {
		return smtp.SendMail(addr, nil, s.from, []string{email}, []byte(msg))
	}

	auth := smtp.PlainAuth("", s.user, s.pass, s.host)
	return smtp.SendMail(addr, auth, s.from, []string{email}, []byte(msg))
}

var _ domain.EmailService = (*SMTPService)(nil)
