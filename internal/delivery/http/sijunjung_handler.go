package http

import (
	"net/http"
)

// SijunjungData represents the sijunjung service data.
// @Description Sijunjung service data
type SijunjungData struct {
	Status string `json:"status" example:"running"`
}

// SijunjungHandler godoc
// @Summary Check Sijunjung service
// @Description Check if Sijunjung service is running
// @Tags sijunjung
// @Security BearerAuth
// @Produce json
// @Success 200 {object} APIResponse{data=SijunjungData} "Service is running"
// @Failure 401 {object} APIErrorResponse "Unauthorized"
// @Router /api/sijunjung [get]
func SijunjungHandler(w http.ResponseWriter, r *http.Request) {
	respondSuccess(w, http.StatusOK, "Sijunjung service is running", SijunjungData{Status: "running"})
}
