package mtr

import (
	"testing"
	"context"

	"github.com/n-ct/ct-monitor/entitylist"
)

const (
	logListPath = "entitylist/log_list.json"

	testLogID = "9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOM="
)

func mustCreateLogClient(t *testing.T) (*LogClient, context.Context, error) {
	t.Helper()
	logList, err := entitylist.NewLogList(logListPath)
	if err != nil {
		t.Fatalf("failed to create loglist at path (%s): %v", logListPath, err)
	}
	logInfo := logList.FindLogByLogID(testLogID)
	if logInfo == nil {
		t.Fatalf("testLogID %s not found in loglist", testLogID)
	}
	logClient, err := NewLogClient(logInfo)
	ctx := context.Background()
	return logClient, ctx, err
}

func TestNewLogClient(t *testing.T) {
	_, _, err := mustCreateLogClient(t)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func mustGetSTH(t *testing.T) (*CTObject, error) {
	t.Helper()
	logClient, ctx, _ := mustCreateLogClient(t)
	return logClient.GetSTH(ctx)
}

func TestGetSTH(t *testing.T) {
	_, err := mustGetSTH(t)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestGetSTHReturnType(t *testing.T) {
	newSTH, _ := mustGetSTH(t)
	var sth interface{} = newSTH
	if _, ok := sth.(*CTObject); !ok {
		t.Fatalf("incorrect data type received from GetSTH: %T", sth)
	}
}

func mustGetSTHWithConsistencyProof(t *testing.T, firstTreeSize, secondTreeSize uint64) (*CTObject, error) {
	t.Helper()
	logClient, ctx, _ := mustCreateLogClient(t)
	return logClient.GetSTHWithConsistencyProof(ctx, firstTreeSize, secondTreeSize)
}

func TestGetSTHWithConsistencyProof(t *testing.T) {
	validFirstTreeSize := uint64(100)
	validSecondTreeSize := uint64(1000)
	_, err := mustGetSTHWithConsistencyProof(t, validFirstTreeSize, validSecondTreeSize)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestGetSTHWithConsistencyProofReturnType(t *testing.T) {
	validFirstTreeSize := uint64(100)
	validSecondTreeSize := uint64(1000)
	newSTHPOC, _ := mustGetSTHWithConsistencyProof(t, validFirstTreeSize, validSecondTreeSize)
	var sthpoc interface{} = newSTHPOC
	if _, ok := sthpoc.(*CTObject); !ok {
		t.Fatalf("incorrect data type received from GetSTH: %T", sthpoc)
	}
}

func mustGetEntryAndProof(t *testing.T, entryIndex, treeSize uint64) (*InclusionProofData, []byte, error) {
	t.Helper()
	logClient, ctx, _ := mustCreateLogClient(t)
	return logClient.GetEntryAndProof(ctx, entryIndex, treeSize)
}

func TestGetEntryAndProof(t *testing.T) {
	validTreeSize := uint64(100)
	validEntryIndex := uint64(4)
	_, _, err := mustGetEntryAndProof(t, validEntryIndex, validTreeSize)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestGetEntryAndProofReturnType(t *testing.T) {
	validTreeSize := uint64(100)
	validEntryIndex := uint64(4)
	newPOI, _, _ := mustGetEntryAndProof(t, validEntryIndex, validTreeSize)
	var poi interface{} = newPOI
	if _, ok := poi.(*InclusionProofData); !ok {
		t.Fatalf("incorrect data type received from GetSTH: %T", poi)
	}
}