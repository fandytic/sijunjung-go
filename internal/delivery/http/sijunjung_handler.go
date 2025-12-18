package http

import "net/http"

func SijunjungHandler(w http.ResponseWriter, r *http.Request) {
	respondSuccess(w, http.StatusOK, map[string]string{
		"message": "Sijunjung service is running.",
	}, "")
}
