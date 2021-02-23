package handler

import (
	//"encoding/json"
	"net/http"
	"github.com/golang/glog"
	"ct-monitor/monitor"
	//"fmt"
)

type Handler struct {
	m *monitor.Monitor
}

func NewHandler(m *monitor.Monitor) Handler {
	return Handler{m}
}

// get-sth, post-revocation, get-inclusion-proof are json-encoded
// for ease of use right now, can be changed later
// get-ocsp uses ocsp request/response ietf specification

// Something to know is that for json decoding to work correctly, all struct var's must be capitalized
type GetInclusionProofRequest struct {
	Serial uint64
}

type GetInclusionProofResponse struct {
	Proof [][]byte
}

// Ocsp Request/Response types defined in revocation-server/ocsp
// asn.1/der encoded

type PostRevocationRequest struct {
	Serial uint64
}

// for mass-revocation event, or for testing
type PostMultipleRevocationsRequest struct {
	Serials []uint64
}

type ProofResponse struct {
	Proof [][]byte
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
	if req.Method != "GET" {
		writeWrongMethodResponse(&rw, "GET")
		return
	}

	/*var sthData *types.SignedLogRoot
	sthData = h.t.GetSth()
	if(sthData==nil) {
		writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Sth is nil pointer"))
	}

	// convert to json
	encoder := json.NewEncoder(rw)
	if err := encoder.Encode(*sthData); err != nil {
		writeErrorResponse(&rw, http.StatusInternalServerError, fmt.Sprintf("Couldn't encode STH to return: %v", err))
		return
	}
	*/
}


func (h *Handler) NewInfo(rw http.ResponseWriter, req *http.Request){
	glog.V(1).Infoln("Received NewInfo Request")
	if req.Method != "GET" {
		writeWrongMethodResponse(&rw, "GET")
		return
	}
}

func (h *Handler) MonitorDomain(rw http.ResponseWriter, req *http.Request){
	glog.V(1).Infoln("Received MonitorDomain Request")
	if req.Method != "GET" {
		writeWrongMethodResponse(&rw, "GET")
		return
	}
}