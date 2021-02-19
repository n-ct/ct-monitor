package mtr 

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/jsonclient"
	"ct-monitor/loglist"
)

// LogClient represents a client for a given CT Log instance
type LogClient struct {
	jsonclient.JSONClient
	log loglist.Log		// loglist.Log Structthat contains the json data about the logger found in loglist.json
}

// New constructs a new LogClient instance.
// |uri| is the base URI of the CT log instance to interact with, e.g.
// https://ct.googleapis.com/pilot
// |hc| is the underlying client to be used for HTTP requests to the CT log.
// |opts| can be used to provide a custom logger interface and a public key
// for signature verification.
func New(uri string, hc *http.Client, opts jsonclient.Options, log *loglist.Log) (*LogClient, error) {
	logClient, err := jsonclient.New(uri, hc, opts)
	if err != nil {
		return nil, err
	}
	return &LogClient{*logClient, *log}, err
}

// Create a LogClient instance to access the log and produce ct v2 data
func NewLogClient(log *loglist.Log) (*LogClient, error){
	uri := log.URL	
	sPubKey := log.Key

	client := &http.Client{}	
	opts := jsonclient.Options{}
	logClient, err := New(uri, client, opts, log)
	if err != nil {
		fmt.Printf("Failed to create logClient")
		return nil, err;
	}

	// Manually create the verifier because passing in string publicKey to opts doesn't seem to work
	pubKey, err := ct.PublicKeyFromB64(sPubKey)
	verifier, err := ct.NewSignatureVerifier(pubKey)
	logClient.Verifier = verifier
	return logClient, err
}

// RspError represents a server error including HTTP information.
type RspError = jsonclient.RspError

// GetSTH retrieves the current STH from the log and produces a SignedTreeHeadData object
// Returns a populated SignedTreeHead, or a non-nil error (which may be of type
// RspError if a raw http.Response is available).
func (c *LogClient) GetSTH(ctx context.Context) (*SignedTreeHeadData, error) {
	// Parse basic response
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

	// Verify that the sth is valid
	// TODO replace this with Monitor's own verification using signature.go file in Monitor
	if err := c.VerifySTHSignature(*sth); err != nil {
		return nil, RspError{Err: err, StatusCode: httpRsp.StatusCode, Body: body}
	}

	// Construct SignedTreeHeadData
	treeHeadSignature := c.ConstructTreeHeadSignatureFromSTH(*sth)
	logID := c.log.LogID
	STHData := &SignedTreeHeadData{logID, treeHeadSignature, sth.TreeHeadSignature}
	return STHData, nil
}

// VerifySTHSignature checks the signature in sth, returning any error encountered or nil if verification is successful.
func (c *LogClient) VerifySTHSignature(sth ct.SignedTreeHead) error {
	if c.Verifier == nil {
		// Can't verify signatures without a verifier
		return nil
	}
	return c.Verifier.VerifySTHSignature(sth)
}

// ConstructTreeHeadSignatureFromSTH constructs a TreeHeadSignature object from sth
func (c *LogClient) ConstructTreeHeadSignatureFromSTH(sth ct.SignedTreeHead) (ct.TreeHeadSignature) {
	treeHeadSignature := ct.TreeHeadSignature{
		Version:        sth.Version,
		SignatureType:  ct.TreeHashSignatureType,
		Timestamp:      sth.Timestamp,
		TreeSize:       sth.TreeSize,
		SHA256RootHash: sth.SHA256RootHash,
	}
	return treeHeadSignature
}

// GetSTHConsistency retrieves the consistency proof between two tree_sizes of the tree
func (c *LogClient) GetSTHConsistency(ctx context.Context, first, second uint64) (*ConsistencyProofData, error) {
	base10 := 10
	params := map[string]string{
		"first":  strconv.FormatUint(first, base10),
		"second": strconv.FormatUint(second, base10),
	}
	var resp ct.GetSTHConsistencyResponse
	if _, _, err := c.GetAndParse(ctx, ct.GetSTHConsistencyPath, params, &resp); err != nil {
		return nil, err
	}

	logID := c.log.LogID
	consistencyProof := &ConsistencyProofData{logID, first, second, resp.Consistency}
	return consistencyProof, nil
}

// GetEntryAndProof returns a log entry and audit path for the index of a leaf.
func (c *LogClient) GetEntryAndProof(ctx context.Context, index, treeSize uint64) (*InclusionProofData, []byte, error) {
	base10 := 10
	params := map[string]string{
		"leaf_index": strconv.FormatUint(index, base10),
		"tree_size":  strconv.FormatUint(treeSize, base10),
	}
	var resp ct.GetEntryAndProofResponse
	if _, _, err := c.GetAndParse(ctx, ct.GetEntryAndProofPath, params, &resp); err != nil {
		return nil, nil, err
	}

	logID := c.log.LogID
	inclusionProof := &InclusionProofData{logID, treeSize, index, resp.AuditPath}
	return inclusionProof, resp.LeafInput,  nil
}

/*func (c *LogClient) GetSTHWithConsistencyProof(ctx context.Context, first, second uint64) (*CTObject, error){
	sth, err := c.GetSTH(ctx)
	if err != nil {
		fmt.Printf("Failed to create STH")
		return nil, nil	// TODO change to a valid error
	}
	poc, err := c.GetSTHConsistency(ctx, 100, 1000)
	if err != nil {
		fmt.Printf("Failed to get Entry and Proof")
		return nil, nil // TODO change to a valid error
	}
	sthWithPoc := &SignedTreeHeadWithConsistencyProof{*sth, *poc}	
}
*/

/*// GetProofByHash returns an audit path for the hash of an SCT.
func (c *LogClient) GetProofByHash(ctx context.Context, hash []byte, treeSize uint64) (*InclusionProofData, error) {
	b64Hash := base64.StdEncoding.EncodeToString(hash)
	base10 := 10
	params := map[string]string{
		"tree_size": strconv.FormatUint(treeSize, base10),
		"hash":      b64Hash,
	}
	var resp ct.GetProofByHashResponse
	if _, _, err := c.GetAndParse(ctx, ct.GetProofByHashPath, params, &resp); err != nil {
		return nil, err
	}

	logID := c.log.LogID
	inclusionProof := &InclusionProofData{logID, treeSize, resp.LeafIndex, resp.AuditPath}
	return inclusionProof, nil
}
*/

