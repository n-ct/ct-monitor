package mtr

import (
	"fmt"
	ct "github.com/google/certificate-transparency-go"
	"ct-monitor/signature"
)

// TODO need to decide if will add signature.go and types.go in tls dir from google repo

type SignedTreeHeadData struct {
	LogID 			string
	TreeHeadData 	ct.TreeHeadSignature
	Signature 		ct.DigitallySigned
}

type ConsistencyProofData struct {
	LogID 			string
	TreeSize1 		uint64
	TreeSize2 		uint64
	ConsistencyPath [][]byte
}

type SignedTreeHeadWithConsistencyProof struct {
	SignedTreeHead SignedTreeHeadData
	ConsistencyProof ConsistencyProofData
}

type InclusionProofData struct {
	LogID 			string
	TreeSize 		uint64
	LeadIndex 		uint64
	InclusionPath 	[][]byte
}

type Alert struct {
	TBS 		AlertSignedFields	// Signed fields of the Alert
	Signature 	ct.DigitallySigned
}

type AlertSignedFields struct {
	AlertType 	 string // Type of Alert. Currently only have Logger Alert for nonresponding Logger
	Signer 		 string	// Signer of the Alert This will be entityID (base64 encoded string of sha256 hash of public key)
	Subject		 string	// Subject of the Alert. Who is the Alert about? This will also be entityID
	Timestamp 	 uint64 // The MMD that the Alert corresponds to
}

type ProofOfMisbehavior struct {
	ProofList []CTObject
}

type AuditOK struct {
	TBS 		AuditOKSignedFields	// Signed fields of the Alert
	Signature 	ct.DigitallySigned
}

type AuditOKSignedFields struct {
	Signer		string	// The Monitor that signs the AuditOK
	Timestamp	uint64	// The timestamp when the AuditOK was created
}

type ObjectIdentifier struct{
	First string
	Second string
	Third uint64
	Fourth string
}

//creates identifier for each type of CTObject
//Alerts [Subject][Signer][Timestamp][Version]
//The rest [TypeID][Subject|Signer][Timestamp][Version]
func (data *CTObject) Identifier() (ObjectIdentifier){
	if data.TypeID == "Alert"{
		return ObjectIdentifier{First: data.Subject, Second: data.Signer, Third: data.Timestamp, Fourth: data.Version.String(),};
	}

	var subjectOrSigner string;
	if len(data.Subject) == 0 {
		subjectOrSigner = data.Signer;
	} else {
		subjectOrSigner = data.Subject;
	}
	return ObjectIdentifier{First: data.TypeID, Second: subjectOrSigner, Third: data.Timestamp, Fourth: data.Version.String(),};
}

type VersionData struct {
	Major uint32
	Minor uint32
	Release uint32
}

func (v VersionData) String() string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

type CTObject struct {
	TypeID 		string // What type of object is found in the blob
	Version		VersionData	// Version of the CTObject
	Timestamp 	uint64 // Timestamp that corresponds to when the blob was created
	Signer 		string // Signer of the data found in the blob
	Subject 	string // Subject of the data found in the blob
	Digest 		[]byte // Typically the hash of the blob
	Blob 		[]byte // An object used in CT converted to byte array
}

func ConstructCTObject(i interface{}) *CTObject {
	var typeID string
	version := VersionData{1,0,0}
	var timestamp uint64
	var signer string 
	var subject string
	var digest []byte 
	var blob []byte

	switch v := i.(type) {
	case *SignedTreeHeadData:
		sth := i.(*SignedTreeHeadData)
		typeID = "STH"
		timestamp = sth.TreeHeadData.Timestamp
		signer = sth.LogID
		blob, _ = signature.SerializeData(sth)
		digest, _, _ = signature.GenerateHash(sth.Signature.Algorithm.Hash, blob)
	
	case *Alert:
		alert := i.(*Alert)
		typeID = "Alert"
		timestamp = alert.TBS.Timestamp
		signer = alert.TBS.Signer
		blob, _ = signature.SerializeData(alert)
		digest, _, _ = signature.GenerateHash(alert.Signature.Algorithm.Hash, blob)
	
	case *SignedTreeHeadWithConsistencyProof:
		sth_poc := i.(*SignedTreeHeadWithConsistencyProof)
		typeID = "STH_POC"
		timestamp = sth_poc.SignedTreeHead.TreeHeadData.Timestamp
		signer = sth_poc.SignedTreeHead.LogID
		blob, _ = signature.SerializeData(sth_poc)
		digest, _, _ = signature.GenerateHash(sth_poc.SignedTreeHead.Signature.Algorithm.Hash, blob)
	
	default:
		fmt.Printf("I don't know about type %T!\n", v)
	}

	ctObject := &CTObject{typeID, version, timestamp, signer, subject, digest, blob}
	return ctObject
}