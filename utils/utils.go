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