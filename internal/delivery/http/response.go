package http

import (
	"encoding/json"
	"net/http"
	"reflect"
)

// APIResponse represents the common envelope for all API responses.
type APIResponse struct {
	Success bool   `json:"success"`
	Data    any    `json:"data"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// respond writes a standardized JSON response to the client.
func respond(w http.ResponseWriter, status int, success bool, data any, message string) {
	if data == nil {
		data = map[string]any{}
	} else {
		value := reflect.ValueOf(data)
		if value.Kind() == reflect.Slice && value.IsNil() {
			data = reflect.MakeSlice(value.Type(), 0, 0).Interface()
		}
	}

	resp := APIResponse{
		Success: success,
		Data:    data,
		Message: message,
		Code:    status,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}

// respondSuccess writes a successful response with the provided status and data.
func respondSuccess(w http.ResponseWriter, status int, data any, message string) {
	respond(w, status, true, data, message)
}

// respondError writes an error response using the standardized structure.
func respondError(w http.ResponseWriter, status int, message string) {
	respond(w, status, false, map[string]any{}, message)
}
