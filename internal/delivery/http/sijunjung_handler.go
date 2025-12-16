package http

import (
	"encoding/json"
	"net/http"
)

func SijunjungHandler(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Sijunjung service is running.",
	})
}
