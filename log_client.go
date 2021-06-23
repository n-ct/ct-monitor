package mtr 

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/golang/glog"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/jsonclient"

	"github.com/n-ct/ct-monitor/entitylist"
)

// LogClient represents a client for a given CT Log instance
type LogClient struct {
	jsonclient.JSONClient
	LogInfo entitylist.LogInfo	// loglist.Log Struct that contains the json data about the logger found in loglist.json
}

// Create a LogClient instance to access the log and produce ct v2 data
func NewLogClient(log *entitylist.LogInfo) (*LogClient, error){
	uri := log.URL	
	client := &http.Client{}	
	opts := jsonclient.Options{}
	logClient, err := newClient(uri, client, opts, log)
	if err != nil {
		return nil, fmt.Errorf("error creating new LogClient for uri %s: %v", uri, err)
	}
	return logClient, nil
}

// New constructs a new LogClient instance.
// |uri| is the base URI of the CT log instance to interact with, e.g.
// https://ct.googleapis.com/pilot
// |hc| is the underlying client to be used for HTTP requests to the CT log.
// |opts| can be used to provide a custom logger interface and a public key
// for signature verification.
func newClient(uri string, hc *http.Client, opts jsonclient.Options, log *entitylist.LogInfo) (*LogClient, error) {
	logClient, err := jsonclient.New(uri, hc, opts)
	if err != nil {
		return nil, err
	}
	return &LogClient{*logClient, *log}, err
}

// RspError represents a server error including HTTP information.
type RspError = jsonclient.RspError

// Get STH and encapsulate it within a CTObject
func (c *LogClient) GetSTH(ctx context.Context) (*CTObject, error) {
	sth, err := c.getSTH(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get STH from Logger %s: %w", c.LogInfo.LogID, err)
	}
	sthCT, err := ConstructCTObject(sth)
	if err != nil {
		return nil, fmt.Errorf("failed to get STH from Logger %s: %w", c.LogInfo.LogID, err)
	}
	glog.Infoln("Received STH from Log")
	return sthCT, nil
}

// GetSTH retrieves the current STH from the log and produces a SignedTreeHeadData object
// Returns a populated SignedTreeHead which is converted into SignedTreeHeaData, or a 
//non-nil error (which may be of type RspError if a raw http.Response is available).
func (c *LogClient) getSTH(ctx context.Context) (*SignedTreeHeadData, error) {
	var resp ct.GetSTHResponse
	httpRsp, body, err := c.GetAndParse(ctx, ct.GetSTHPath, nil, &resp)
	if err != nil {
		return nil, err
	}

	// Convert basic response to simple sth object
	sth, err := resp.ToSignedTreeHead()
	if err != nil {
		return nil, RspError{Err: err, StatusCode: httpRsp.StatusCode, Body: body}
	}

	// Construct ctv2 SignedTreeHeadData
	treeHeadSignature := c.constructTreeHeadSignatureFromSTH(sth)
	logID := c.LogInfo.LogID
	STHData := &SignedTreeHeadData{logID, treeHeadSignature, sth.TreeHeadSignature}
	return STHData, nil
}

// Construct a TreeHeadSignature object from normal Logger response sth
func (c *LogClient) constructTreeHeadSignatureFromSTH(sth *ct.SignedTreeHead) ct.TreeHeadSignature {
	treeHeadSignature := ct.TreeHeadSignature{
		Version:        sth.Version,
		SignatureType:  ct.TreeHashSignatureType,
		Timestamp:      sth.Timestamp,
		TreeSize:       sth.TreeSize,
		SHA256RootHash: sth.SHA256RootHash,
	}
	return treeHeadSignature
}

// Get STH and ConsistencyProof to construt SignedTreeHeadWithConsistencyProof CTObject
func (c *LogClient) GetSTHWithConsistencyProof(ctx context.Context, first, second uint64) (*CTObject, error){
	sth, err := c.getSTH(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to first get STH when getting STHWithPoC from Logger %s: %w", c.LogInfo.LogID, err)
	}
	poc, err := c.getConsistencyProof(ctx, first, second)
	if err != nil {
		return nil, fmt.Errorf("failed to first get PoC when getting STHWithPoC from Logger %s: %w", c.LogInfo.LogID, err)
	}
	sthWithPoc := &SignedTreeHeadWithConsistencyProof{*sth, *poc}	
	sthWithPOCCT, err := ConstructCTObject(sthWithPoc)
	if err != nil {
		return nil, fmt.Errorf("failed to construct STHWithPoC CTObject for Logger %s: %w", c.LogInfo.LogID, err)
	}
	return sthWithPOCCT, nil
}

// Retrieves the consistency proof between two tree_sizes of the tree
func (c *LogClient) getConsistencyProof(ctx context.Context, first, second uint64) (*ConsistencyProofData, error) {
	base10 := 10
	params := map[string]string{
		"first":  strconv.FormatUint(first, base10),
		"second": strconv.FormatUint(second, base10),
	}
	var resp ct.GetSTHConsistencyResponse
	if _, _, err := c.GetAndParse(ctx, ct.GetSTHConsistencyPath, params, &resp); err != nil {
		return nil, fmt.Errorf("failed to get ConsistencyProof from Logger %s: %w", c.LogInfo.LogID, err)
	}

	// Construct ctv2 ConsistencyProofData
	logID := c.LogInfo.LogID
	consistencyProof := &ConsistencyProofData{logID, first, second, resp.Consistency}
	return consistencyProof, nil
}

// Return a log entry and audit path for the given index of a leaf.and treeSize of the tree
func (c *LogClient) GetEntryAndProof(ctx context.Context, index, treeSize uint64) (*InclusionProofData, []byte, error) {
	base10 := 10
	params := map[string]string{
		"leaf_index": strconv.FormatUint(index, base10),
		"tree_size":  strconv.FormatUint(treeSize, base10),
	}
	var resp ct.GetEntryAndProofResponse
	if _, _, err := c.GetAndParse(ctx, ct.GetEntryAndProofPath, params, &resp); err != nil {
		return nil, nil, fmt.Errorf("failed to get EntryAndProof from Logger %s: %w", c.LogInfo.LogID, err)
	}

	// Construct ctv2 InclusionProofData
	logID := c.LogInfo.LogID
	inclusionProof := &InclusionProofData{logID, treeSize, index, resp.AuditPath}
	return inclusionProof, resp.LeafInput,  nil
}