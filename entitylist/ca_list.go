// Copyright 2018 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package loglist2 allows parsing and searching of the master CT Log list.
// It expects the log list to conform to the v2beta schema.

package entitylist

import (
	"fmt"
	"strings"
	"encoding/json"

	"github.com/n-ct/ct-monitor/utils"
)

// CAList holds a collection of CT CAs, grouped by operator.
type CAList struct {
	// CAOperators is a list of CA operators and the CAs they operate.
	CAOperators []*CAOperator `json:"operators"`
}

// CAOperator holds a collection of CAs run by the same organisation.
// It also provides information about that organisation, e.g. contact details.
type CAOperator struct {
	// Name is the name of the CT CA Operator.
	Name  string `json:"name"`
	// Email lists the email addresses that can be used to contact this log
	// operator.
	Email []string `json:"email"`
	// CAs is a list of CT CAs run by this operator.
	CAs   []*CAInfo `json:"cas"`
}

// CAInfo describes a single CA.
type CAInfo struct {
	// CAID is the SHA-256 hash of the CA's public key.
	CAID  string `json:"ca_id"`
	// Key is the public key with which signatures can be verified.
	CAKey string `json:"ca_key"`
	// URL is the address of the HTTPS API for the CA.
	CAURL string `json:"ca_url"`
	// MMD is the amount of seconds the CA takes to add new revocations to its data structures
	MMD   uint64 `json:"mmd"`
}

// Create new CAList
func NewCAList(caListName string) (*CAList, error) {
	byteData, err := utils.FiletoBytes(caListName)
	if err != nil {
		return nil, fmt.Errorf("error opening %s to create new CAList: %w", caListName, err)
	}
	caList, err := newCAListFromJSON(byteData)
	if err != nil {
		return nil, fmt.Errorf("error reading %s to create new CAList: %w", caListName, err)
	}
	return caList, nil
}

// NewFromJSON creates a LogList from JSON encoded data.
func newCAListFromJSON(clData []byte) (*CAList, error) {
	var cl CAList
	if err := json.Unmarshal(clData, &cl); err != nil {
		return nil, fmt.Errorf("failed to parse ca list: %v", err)
	}
	return &cl, nil
}

// FindCAByCAID finds the CAInfo with the given caID string
func (cl *CAList) FindCAByCAID(CAID string) *CAInfo {
	for _, op := range cl.CAOperators {
		for _, ca := range op.CAs {
			if (strings.Contains(ca.CAID, CAID)){
				return ca 
			}
		}
	}
	return nil
}

// FindCAByCAID finds the CAInfo with the given url string
func (ml *CAList) FindCAByCAURL(caURL string) *CAInfo {
	for _, op := range ml.CAOperators {
		for _, ca := range op.CAs {
			if (strings.Contains(ca.CAURL, caURL)){
				return ca 
			}
		}
	}
	return nil
}