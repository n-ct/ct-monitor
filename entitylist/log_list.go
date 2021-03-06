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
	"time"
	"encoding/json"

	"github.com/n-ct/ct-monitor/utils"
)

// LogList holds a collection of CT logs, grouped by operator.
type LogList struct {
	// Operators is a list of CT log operators and the logs they operate.
	Operators []*Operator `json:"operators"`
}

// Operator holds a collection of CT logs run by the same organisation.
// It also provides information about that organisation, e.g. contact details.
type Operator struct {
	// Name is the name of the CT log operator.
	Name string `json:"name"`
	// Email lists the email addresses that can be used to contact this log
	// operator.
	Email []string `json:"email"`
	// Logs is a list of CT logs run by this operator.
	Logs []*LogInfo `json:"logs"`
}

// Log describes a single CT log.
type LogInfo struct {
	// Description is a human-readable string that describes the log.
	Description string `json:"description,omitempty"`
	// LogID is the SHA-256 hash of the log's public key.
	//LogID []byte `json:"log_id"`
	LogID string `json:"log_id"`
	// Key is the public key with which signatures can be verified.
	Key string `json:"key"`
	// URL is the address of the HTTPS API.
	URL string `json:"url"`
	// DNS is the address of the DNS API.
	DNS string `json:"dns,omitempty"`
	// MMD is the Maximum Merge Delay, in seconds. All submitted
	// certificates must be incorporated into the log within this time.
	MMD int32 `json:"mmd"`
	// State is the current state of the log, from the perspective of the
	// log list distributor.
	State *LogStates `json:"state,omitempty"`
	// TemporalInterval, if set, indicates that this log only accepts
	// certificates with a NotBefore date in this time range.
	TemporalInterval *TemporalInterval `json:"temporal_interval,omitempty"`
	// Type indicates the purpose of this log, e.g. "test" or "prod".
	Type string `json:"log_type,omitempty"`
	// MMDEnd indicates the utc hour and minutes that the mmd of the log will end. By default, seconds will be 0
	MMDEnd *ClockTime `json:"mmd_end"`
	// MMDAccessDelay indicates the amount of seconds that one can access the daily object after MMDEnd
	MMDAccessDelay uint32 `json:"mmd_access_delay"`
}

// ClockTime has the UTC hour, minute, and second corresponding to a specific time in a day
type ClockTime struct {
	Hour uint8 `json:"hour"`
	Minute uint8 `json:"minute"`
	Second uint8 `json:"second"`
}

// TemporalInterval is a time range.
type TemporalInterval struct {
	// StartInclusive is the beginning of the time range.
	StartInclusive time.Time `json:"start_inclusive"`
	// EndExclusive is just after the end of the time range.
	EndExclusive time.Time `json:"end_exclusive"`
}

// LogStatus indicates Log status.
type LogStatus int

// LogStatus values
const (
	UndefinedLogStatus LogStatus = iota
	PendingLogStatus
	QualifiedLogStatus
	UsableLogStatus
	ReadOnlyLogStatus
	RetiredLogStatus
	RejectedLogStatus
)

// LogStates are the states that a CT log can be in, from the perspective of a
// user agent. Only one should be set - this is the current state.
type LogStates struct {
	// Pending indicates that the log is in the "pending" state.
	Pending *LogState `json:"pending,omitempty"`
	// Qualified indicates that the log is in the "qualified" state.
	Qualified *LogState `json:"qualified,omitempty"`
	// Usable indicates that the log is in the "usable" state.
	Usable *LogState `json:"usable,omitempty"`
	// ReadOnly indicates that the log is in the "readonly" state.
	ReadOnly *ReadOnlyLogState `json:"readonly,omitempty"`
	// Retired indicates that the log is in the "retired" state.
	Retired *LogState `json:"retired,omitempty"`
	// Rejected indicates that the log is in the "rejected" state.
	Rejected *LogState `json:"rejected,omitempty"`
}

// LogState contains details on the current state of a CT log.
type LogState struct {
	// Timestamp is the time when the state began.
	Timestamp time.Time `json:"timestamp"`
}

// ReadOnlyLogState contains details on the current state of a read-only CT log.
type ReadOnlyLogState struct {
	LogState
	// FinalTreeHead is the root hash and tree size at which the CT log was
	// made read-only. This should never change while the log is read-only.
	FinalTreeHead TreeHead `json:"final_tree_head"`
}

// TreeHead is the root hash and tree size of a CT log.
type TreeHead struct {
	// SHA256RootHash is the root hash of the CT log's Merkle tree.
	SHA256RootHash []byte `json:"sha256_root_hash"`
	// TreeSize is the size of the CT log's Merkle tree.
	TreeSize int64 `json:"tree_size"`
}

// LogStatus method returns Log-status enum value for descriptive struct.
func (ls *LogStates) LogStatus() LogStatus {
	switch {
	case ls == nil:
		return UndefinedLogStatus
	case ls.Pending != nil:
		return PendingLogStatus
	case ls.Qualified != nil:
		return QualifiedLogStatus
	case ls.Usable != nil:
		return UsableLogStatus
	case ls.ReadOnly != nil:
		return ReadOnlyLogStatus
	case ls.Retired != nil:
		return RetiredLogStatus
	case ls.Rejected != nil:
		return RejectedLogStatus
	default:
		return UndefinedLogStatus
	}
}

// Active picks the set-up state. If multiple states are set (not expected) picks one of them.
func (ls *LogStates) Active() (*LogState, *ReadOnlyLogState) {
	if ls == nil {
		return nil, nil
	}
	switch {
	case ls.Pending != nil:
		return ls.Pending, nil
	case ls.Qualified != nil:
		return ls.Qualified, nil
	case ls.Usable != nil:
		return ls.Usable, nil
	case ls.ReadOnly != nil:
		return nil, ls.ReadOnly
	case ls.Retired != nil:
		return ls.Retired, nil
	case ls.Rejected != nil:
		return ls.Rejected, nil
	default:
		return nil, nil
	}
}

// Create new LogList
func NewLogList(logListName string) (*LogList, error) {
	byteData, err := utils.FiletoBytes(logListName)
	if err != nil {
		return nil, fmt.Errorf("error opening %s to create new LogList: %w", logListName, err)
	}
	logList, err := newLogListFromJSON(byteData)
	if err != nil {
		return nil, fmt.Errorf("error reading %s to create new LogList: %w", logListName, err)
	}
	return logList, nil
}

// NewFromJSON creates a LogList from JSON encoded data.
func newLogListFromJSON(llData []byte) (*LogList, error) {
	var ll LogList
	if err := json.Unmarshal(llData, &ll); err != nil {
		return nil, fmt.Errorf("failed to parse log list: %v", err)
	}
	return &ll, nil
}

// FindLogByLogID finds the log with the given logID string
func (ll *LogList) FindLogByLogID(logID string) *LogInfo {
	for _, op := range ll.Operators {
		for _, log := range op.Logs {
			if log.LogID == logID {
				return log
			}
		}
	}
	return nil
}