package whatsapp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FonnteResponse represents the response from Fonnte API.
type FonnteResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"reason"`
}

// FonnteService implements WhatsAppService using Fonnte API.
type FonnteService struct {
	token string
}

// NewFonnteService creates a new Fonnte WhatsApp service.
func NewFonnteService(token string) *FonnteService {
	return &FonnteService{token: token}
}

// SendOTP sends an OTP code via WhatsApp using Fonnte API.
func (s *FonnteService) SendOTP(ctx context.Context, phone, code string) error {
	if s.token == "" {
		return errors.New("WhatsApp service tidak dikonfigurasi")
	}

	message := "Kode verifikasi Anda adalah: " + code + "\n\nKode ini berlaku selama 5 menit. Jangan bagikan kode ini kepada siapapun.\n\n- Sijunjung Go"

	data := url.Values{}
	data.Set("target", phone)
	data.Set("message", message)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.fonnte.com/send", strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", s.token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("Gagal mengirim pesan WhatsApp")
	}
	defer resp.Body.Close()

	var result FonnteResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return errors.New("Gagal memproses response dari WhatsApp service")
	}

	if !result.Status {
		return errors.New("Gagal mengirim pesan WhatsApp: " + result.Message)
	}

	return nil
}
