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

// MonitorList holds a collection of CT Monitors, grouped by operator.
type MonitorList struct {
	// MonitorOperators is a list of Monitor operators and the Monitors they operate.
	MonitorOperators []*MonitorOperator `json:"operators"`
}

// MonitorOperator holds a collection of Monitors run by the same organisation.
// It also provides information about that organisation, e.g. contact details.
type MonitorOperator struct {
	// Name is the name of the CT Monitor Operator.
	Name string `json:"name"`
	// Email lists the email addresses that can be used to contact this log
	// operator.
	Email []string `json:"email"`
	// Monitors is a list of CT Monitors run by this operator.
	Monitors []*MonitorInfo `json:"monitors"`
}

// MonitorInfo describes a single Monitor.
type MonitorInfo struct {
	// MonitorID is the SHA-256 hash of the Monitor's public key.
	MonitorID string `json:"monitor_id"`
	// Key is the public key with which signatures can be verified.
	MonitorKey string `json:"monitor_key"`
	// URL is the address of the HTTPS API for the Monitor.
	MonitorURL string `json:"monitor_url"`
	// URL is the address of the HTTPS API for the Gossiper.
	GossiperURL string `json:"gossiper_url"`
}

// Create new MonitorList
func NewMonitorList(monitorListName string) (*MonitorList, error) {
	byteData, err := utils.FiletoBytes(monitorListName)
	if err != nil {
		return nil, fmt.Errorf("error opening %s to create new MonitorList: %w", monitorListName, err)
	}
	monitorList, err := newMonitorListFromJSON(byteData)
	if err != nil {
		return nil, fmt.Errorf("error reading %s to create new MonitorList: %w", monitorListName, err)
	}
	return monitorList, nil
}

// NewFromJSON creates a LogList from JSON encoded data.
func newMonitorListFromJSON(mlData []byte) (*MonitorList, error) {
	var ml MonitorList
	if err := json.Unmarshal(mlData, &ml); err != nil {
		return nil, fmt.Errorf("failed to parse monitor list: %v", err)
	}
	return &ml, nil
}

// FindMonitorByMonitorID finds the MonitorInfo with the given monitorID string
func (ml *MonitorList) FindMonitorByMonitorID(monitorID string) *MonitorInfo {
	for _, op := range ml.MonitorOperators {
		for _, mon := range op.Monitors {
			if mon.MonitorID == monitorID {
				return mon 
			}
		}
	}
	return nil
}

// FindMonitorByMonitorID finds the MonitorInfo with the given url string
func (ml *MonitorList) FindMonitorByMonitorURL(monitorURL string) *MonitorInfo {
	for _, op := range ml.MonitorOperators {
		for _, mon := range op.Monitors {
			if (strings.Contains(mon.MonitorURL, monitorURL)){
				return mon 
			}
		}
	}
	return nil
}