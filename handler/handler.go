package handler

import (
	"fmt"
	"encoding/json"
	"net/http"

	"github.com/golang/glog"

	mtr "github.com/n-ct/ct-monitor"
	"github.com/n-ct/ct-monitor/monitor"
)

type Handler struct {
	m *monitor.Monitor
}

func NewHandler(m *monitor.Monitor) Handler {
	return Handler{m}
}

func writeWrongMethodResponse(rw *http.ResponseWriter, allowed string) {
	(*rw).Header().Add("Allow", allowed)
	(*rw).WriteHeader(http.StatusMethodNotAllowed)
}

func writeErrorResponse(rw *http.ResponseWriter, status int, body string) {
	(*rw).WriteHeader(status)
	(*rw).Write([]byte(body))
}

func (h *Handler) Audit(rw http.ResponseWriter, req *http.Request){
	glog.V(1).Infoln("Received Audit Request")
	if req.Method != "POST" {
		writeWrongMethodResponse(&rw, "GET")
		return
	}

	decoder := json.NewDecoder(req.Body)
	var ctObject mtr.CTObject
	if err := decoder.Decode(&ctObject); err != nil {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("Invalid Audit Request: %v", err))
		return
	}

	if ctObject.TypeID != mtr.STHTypeID{
		writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Invalid STH CTObject. Need %s", mtr.STHTypeID))
		return
	}

	// Get ctObject audit response. This can either be PoM CTObject or AuditOK CTObject
	auditResp, err := h.m.AuditSTH(&ctObject)
	if err != nil {
		writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("failed to audit: %v", err))
		return
	}
	encoder := json.NewEncoder(rw)
	if err := encoder.Encode(*auditResp); err != nil {
		writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Couldn't encode Audit Response to return: %v", err))
		return
	}
	rw.WriteHeader(http.StatusOK)
}


func (h *Handler) NewInfo(rw http.ResponseWriter, req *http.Request){
	glog.V(1).Infoln("Received NewInfo Request")
	if req.Method != "POST" {
		writeWrongMethodResponse(&rw, "POST")
		return
	}

	decoder := json.NewDecoder(req.Body)
	var ctObject mtr.CTObject
	if err := decoder.Decode(&ctObject); err != nil {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("Invalid NewInfo Request: %v", err))
		return
	}

	if err := h.m.AddEntry(&ctObject); err != nil {
		writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Unable to store object: %v", err))
		return
	}
	rw.WriteHeader(http.StatusOK)
}

func (h *Handler) MonitorDomain(rw http.ResponseWriter, req *http.Request){
	glog.V(1).Infoln("Received MonitorDomain Request")
	if req.Method != "POST" {
		writeWrongMethodResponse(&rw, "POST")
		return
	}
}

func (h *Handler) STHGossip(rw http.ResponseWriter, req *http.Request) {

}