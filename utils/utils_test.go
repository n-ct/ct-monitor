package utils

import (
	"testing"
	"bytes"
)

const (
	testJSONPath = "../testdata/test_json.json"
)

var (
	testJSONBytes = []byte{123, 10, 32, 32, 32, 32, 34, 116, 101, 115, 116, 68, 97, 116, 97, 34, 58, 32, 49, 10, 125} 
)

func mustConvertFileToBytes(t  *testing.T) ([]byte, error) {
	t.Helper()
	return FiletoBytes(testJSONPath)
}

func TestFileToBytes(t *testing.T) {
	byteData, err := mustConvertFileToBytes(t)
	if err != nil {
		t.Fatalf("failed to convert %s to bytes: %v", testJSONPath, err)
	}

	if !bytes.Equal(byteData, testJSONBytes) {
		t.Fatalf("parsed bytes not equal to testJSONBytes: %v", byteData)
	}
}

func TestCreateRequestURL(t *testing.T) {
	tests := []struct {
		address			   string
		endpointPath	   string
		expectedRequestURL string
	}{
		{
			address: "addr/",
			endpointPath: "/path",
			expectedRequestURL: "addr/path",
		},
		{
			address: "addr",
			endpointPath: "/path",
			expectedRequestURL: "addr/path",	
		},
		{
			address: "addr/",
			endpointPath: "path",
			expectedRequestURL: "addr/path",	
		},
		{
			address: "addr",
			endpointPath: "path",
			expectedRequestURL: "addr/path",	
		},
	}

	for _, test := range tests {
		reqURL := CreateRequestURL(test.address, test.endpointPath)
		if reqURL != test.expectedRequestURL {
			t.Errorf("failed to create request URL: %s", reqURL)
		}
	}
}
