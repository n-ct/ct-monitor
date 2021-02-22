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
	"encoding/json"
	"fmt"
	"strings"

	"ct-monitor/utils"
)

// LogList holds a collection of CT logs, grouped by operator.
type MonitorList struct {
	// Operators is a list of CT log operators and the logs they operate.
	MonitorOperators []*MonitorOperator `json:"operators"`
}

// Operator holds a collection of CT logs run by the same organisation.
// It also provides information about that organisation, e.g. contact details.
type MonitorOperator struct {
	// Name is the name of the CT log operator.
	Name string `json:"name"`
	// Email lists the email addresses that can be used to contact this log
	// operator.
	Email []string `json:"email"`
	// Logs is a list of CT logs run by this operator.
	Monitors []*MonitorInfo `json:"monitors"`
}

// Log describes a single CT log.
type MonitorInfo struct {
	// LogID is the SHA-256 hash of the log's public key.
	//LogID []byte `json:"log_id"`
	MonitorID string `json:"monitor_id"`
	// Key is the public key with which signatures can be verified.
	MonitorKey string `json:"monitor_key"`
	// URL is the address of the HTTPS API.
	MonitorURL string `json:"monitor_url"`
	// URL is the address of the HTTPS API.
	GossiperURL string `json:"gossiper_url"`
}

// Create new MonitorList
func NewMonitorList(monitorListName string) *MonitorList{
	byteData := utils.JSONFiletoBytes(monitorListName)
	monitorList, err := NewMonitorListFromJSON(byteData)
	if err != nil {
		return nil
	}
	return monitorList
}

// NewFromJSON creates a LogList from JSON encoded data.
func NewMonitorListFromJSON(mlData []byte) (*MonitorList, error) {
	var ml MonitorList
	if err := json.Unmarshal(mlData, &ml); err != nil {
		return nil, fmt.Errorf("failed to parse log list: %v", err)
	}
	return &ml, nil
}

// FindMonitorByMonitorID finds the MonitorInfo with the given monitorID string
func (ml *MonitorList) FindMonitorByMonitorID(monitorID string) *MonitorInfo {
	for _, op := range ml.MonitorOperators {
		for _, mon := range op.Monitors {
			if (strings.Contains(mon.MonitorID, monitorID)){
				return mon 
			}
		}
	}
	return nil
}