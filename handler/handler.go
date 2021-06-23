package handler

import (
	"fmt"
	"context"
	"encoding/json"
	"net/http"

	"github.com/golang/glog"

	mtr "github.com/n-ct/ct-monitor"
	"github.com/n-ct/ct-monitor/monitor"
	"github.com/n-ct/ct-monitor/utils"
)

type Handler struct {
	m *monitor.Monitor
}

// Create new instance of the Handler class
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

// Handle an audit request from a Relying Party
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

	if ctObject.TypeID != mtr.STHTypeID && ctObject.TypeID != mtr.SRDWithRevDataTypeID{
		writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Invalid STH or SRD CTObject. Need %s", mtr.STHTypeID))
		return
	}

	// Get ctObject audit response. This can either be PoM CTObject or AuditOK CTObject
	auditResp, err := h.m.Audit(&ctObject)
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

// Handle receiving new data from another party
func (h *Handler) NewInfo(rw http.ResponseWriter, req *http.Request){
	glog.Infoln("Received NewInfo Request")
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

// Handle a request from another party to monitor a specific domain
func (h *Handler) MonitorDomain(rw http.ResponseWriter, req *http.Request){
	glog.V(1).Infoln("Received MonitorDomain Request")
	if req.Method != "POST" {
		writeWrongMethodResponse(&rw, "POST")
		return
	}
}

// Handle request to get an STH from a specific Logger and then to gossip to peers
func (h *Handler) STHGossip(rw http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		writeWrongMethodResponse(&rw, "GET")
		return
	}
	glog.Infoln("Received STHGossip request")
	logID, ok := req.URL.Query()["log-id"]
	if !ok {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("STHGossip request missing log-id param"))
		return
	}
	logClient, ok := h.m.LogIDMap[logID[0]]
	if !ok {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("STHGossip request log-id param value invalid. %v log-id not found in Monitor's LogIDMap", logID))
		return
	}
	ctx := context.Background()
	sth, err := logClient.GetSTH(ctx)
	if err != nil {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("Monitor failed to getSTH from logger with log-id (%v): %v", logID, err))
		return
	}
	h.m.Gossip(sth)
	rw.WriteHeader(http.StatusOK)
}

// Handle request to get an STHWithPOC from a specific Logger and then to gossip to peers
func (h *Handler) STHWithPOCGossip(rw http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		writeWrongMethodResponse(&rw, "GET")
		return
	}
	glog.Infoln("Received STHWithPOCGossip request")
	decoder := json.NewDecoder(req.Body)
	var sthPOCGosReq mtr.STHWithPOCGossipRequest
	if err := decoder.Decode(&sthPOCGosReq); err != nil {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("Invalid STHWithPOCGossipRequest: %v", err))
		return
	}

	logClient, ok := h.m.LogIDMap[sthPOCGosReq.LogID]
	if !ok {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("STHWithPOCGossip request log-id param value invalid. %v log-id not found in Monitor's LogIDMap", sthPOCGosReq.LogID))
		return
	}
	ctx := context.Background()
	sth, err := logClient.GetSTHWithConsistencyProof(ctx, sthPOCGosReq.FirstTreeSize, sthPOCGosReq.SecondTreeSize)
	if err != nil {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("Monitor failed to getSTHWithPoC from logger with log-id (%v): %v", sthPOCGosReq.LogID, err))
		return
	}

	// Log the size of the object
	size, err := utils.GetSize(sth)
	glog.Infof("Size of sth CTObject is %v: %v", size, err)
	h.m.Gossip(sth)
	rw.WriteHeader(http.StatusOK)
}

// Handle request to get an SRD from a specific Logger and then to gossip to peers
func (h *Handler) SRDWithRevDataGossip(rw http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		writeWrongMethodResponse(&rw, "GET")
		return
	}
	glog.Infoln("Received SRDWithRevDataGossip request")
	decoder := json.NewDecoder(req.Body)
	var srdGosReq mtr.SRDWithRevDataGossipRequest
	if err := decoder.Decode(&srdGosReq); err != nil {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("Invalid SRDWithRevDataGossipRequest: %v", err))
		return
	}
	logClient, ok := h.m.LogIDMap[srdGosReq.LogID]
	if !ok {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("SRDWithRevDataGossip request log-id param value invalid. %v log-id not found in Monitor's LogIDMap", srdGosReq.LogID))
		return
	}
	srdCTObj, err := h.m.GetSRDWithRevData(logClient.LogInfo.URL, &srdGosReq)
	if err != nil {
		writeErrorResponse(&rw, http.StatusBadRequest, fmt.Sprintf("Monitor failed to getSRDWithRevData from logger with log-id (%v): %v", srdGosReq.LogID, err))
		return
	}

	// Log the size of the object
	size, err := utils.GetSize(srdCTObj)
	glog.Infof("Size of srd CTObject is %v: %v", size, err)
	h.m.Gossip(srdCTObj)
	rw.WriteHeader(http.StatusOK)
}