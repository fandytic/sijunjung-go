package http

import (
	"encoding/json"
	"net/http"
	"reflect"
)

// APIResponse represents the common envelope for all API responses.
// @Description Standard API response
type APIResponse struct {
	Success bool   `json:"success" example:"true"`
	Data    any    `json:"data" swaggertype:"object"`
	Message string `json:"message" example:"operation successful"`
	Code    int    `json:"code" example:"200"`
}

// APIErrorResponse represents the standard API error response format (without data field).
// @Description Standard API error response
type APIErrorResponse struct {
	Success bool   `json:"success" example:"false"`
	Message string `json:"message" example:"invalid request"`
	Code    int    `json:"code" example:"400"`
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
func respondSuccess(w http.ResponseWriter, status int, message string, data any) {
	respond(w, status, true, data, message)
}

// respondSuccessNoData sends a successful JSON response without data.
func respondSuccessNoData(w http.ResponseWriter, code int, message string) {
	respond(w, code, true, map[string]any{}, message)
}

// respondError writes an error response using the standardized structure.
func respondError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(APIErrorResponse{
		Success: false,
		Message: message,
		Code:    status,
	})
}
