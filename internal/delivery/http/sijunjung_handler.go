package http

import (
	"encoding/json"
	"net/http"
)

func SijunjungHandler(w http.ResponseWriter, r *http.Request) {
	if err := json.NewEncoder(w).Encode(map[string]string{
		"message": "Sijunjung service is running.",
	}); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}
