package mtr

import (
	ct "github.com/google/certificate-transparency-go"
)


type SignedTreeHeadData struct {
	LogID string
	TreeHeadData ct.TreeHeadSignature
	Signature ct.DigitallySigned
}

type ConsistencyProofData struct {
	LogID string
	TreeSize1 uint64
	TreeSize2 uint64
	ConsistencyPath [][]byte
}

type InclusionProofData struct {
	LogID string
	TreeSize uint64
	LeadIndex uint64
	InclusionPath [][]byte
}
