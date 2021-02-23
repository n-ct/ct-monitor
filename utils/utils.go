package utils

import (
	"fmt"
	"io/ioutil"
	"os"
)

// Opens a json file and parses it as bytes
func JSONFiletoBytes(fileName string) []byte{
	jsonFile, err := os.Open(fileName)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Successfully Opened %s\n", fileName)
	byteData, _ := ioutil.ReadAll(jsonFile)
	jsonFile.Close()
	return byteData
}

func CreateRequestURL(address string, endpointURL string) string{
	if address[len(address) - 1:] == "/" {
		address = address[:len(address) - 1]
	}
	if endpointURL[:1] == "/" {
		endpointURL = endpointURL[1:]
	}
	return address + "/" + endpointURL
}