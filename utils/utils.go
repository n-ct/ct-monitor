package utils

import (
	"fmt"
	"os"
	"strings"
	"io/ioutil"
	"bytes"
	"encoding/json"
)

// Open a file and parse it as bytes
func FiletoBytes(fileName string) ([]byte, error) {
	jsonFile, err := os.Open(fileName)
	defer jsonFile.Close()
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)	
	}
	//fmt.Printf("Successfully Opened %s\n", fileName)	// TODO Replace with log later
	byteData, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, fmt.Errorf("error reading from file %s: %v", fileName, err)
	}
	return byteData, nil
}

// Given address and endpointPath, construct the url with correct number of forward slashes
func CreateRequestURL(address string, endpointPath string) string {
	forwardSlash := "/"
	if strings.HasSuffix(address, forwardSlash) {
		address = strings.TrimSuffix(address, forwardSlash)
	}
	if strings.HasPrefix(endpointPath, forwardSlash) {
		endpointPath = strings.TrimPrefix(endpointPath, forwardSlash)
	}
	return address + forwardSlash + endpointPath
}

// Convert an object to json and get the size
func GetSize(i interface{}) (int, error) {
	b := new(bytes.Buffer)
    if err := json.NewEncoder(b).Encode(i); err != nil {
		return 0, fmt.Errorf("Failed to encode object of type (%T): %v", i, err)
	}
	return b.Len(), nil
}