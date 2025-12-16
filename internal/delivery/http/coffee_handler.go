package http

import (
	"encoding/json"
	"net/http"
)

// CoffeeHandler returns a simple message demonstrating a working endpoint.
// @Summary      Sample protected endpoint
// @Description  Returns a simple message to show the service is running.
// @Tags         examples
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]string
// @Router       /coffee [get]
func CoffeeHandler(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Coffee chat service is running.",
	})
}
