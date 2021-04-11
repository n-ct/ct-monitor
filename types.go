package mtr

import (
	"fmt"
	"encoding/json"
	"bytes"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"

	"github.com/n-ct/ct-monitor/signature"
)

// Endpoint path const variables
const (
	AuditPath 		  			= "/ct/v1/audit"
	NewInfoPath		  			= "/ct/v1/new-info"
	MonitorDomainPath 			= "/ct/v1/monitor-domain"
	STHGossipPath	  			= "/ct/v1/sth-gossip"
	STHWithPOCGossipPath 		= "/ct/v1/sth-with-poc-gossip"
	SRDWithRevDataGossipPath 	= "/ct/v1/srd-with-revdata-gossip"
)

type STHWithPOCGossipRequest struct {
	LogID 			string
	FirstTreeSize 	uint64
	SecondTreeSize 	uint64
}

type SRDWithRevDataGossipRequest struct {
	LogID 			string
	PercentRevoked 	uint8
	TotalCerts 		uint64
}

// TypeID const variables
const (
	STHTypeID 					= "STH"
	STHPOCTypeID 				= "STH_POC"
	AlertTypeID 				= "ALERT"
	ConflictingSTHPOMTypeID 	= "POM_CONFLICTING_STH"
	ConflictingSRDPOMTypeID 	= "POM_CONFLICTING_SRD"
	NonRespondingLogPOMTypeID 	= "POM_NONRESPONDING_LOG"
	SRDAuditOKTypeID			= "SRD_AUDIT_OK"
	STHAuditOKTypeID			= "STH_AUDIT_OK"

	// Revocation transparency data
	SRDWithRevDataTypeID 		= "SRD_REVDATA"
)

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
	SignedTreeHead	 SignedTreeHeadData
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

type ConflictingSTHPOM struct {
	STH1	SignedTreeHeadData
	STH2	SignedTreeHeadData
}

type ConflictingSRDPOM struct {
	SRD1	SignedRevocationDigest
	SRD2	SignedRevocationDigest
}

type NonRespondingLogPOM struct {
	AlertList []Alert
}

type AuditOK struct {
	STH			SignedTreeHeadData
	Signature 	ct.DigitallySigned
}

type SRDAuditOK struct {
	SRD			SignedRevocationDigest
	Signature 	ct.DigitallySigned
}

type STHAuditOK struct {
	STH			SignedTreeHeadData
	Signature 	ct.DigitallySigned
}

// Revocation transparency data
type RevocationData struct {
	EntityID 	string
	RevocationType 	string
	Timestamp 	uint64
	CRVDelta	[]byte	// CRVDelta will always be compressed
}

type RevocationDigest struct {
	Timestamp 	 uint64
	CRVHash		 []byte
	CRVDeltaHash []byte
}

type SignedRevocationDigest struct {
	EntityID 	string
	RevDigest	RevocationDigest	
	Signature	ct.DigitallySigned
}

type SRDWithRevData struct {
	RevData		RevocationData
	SRD			SignedRevocationDigest
}

type ObjectIdentifier struct{
	First  string
	Second string
	Third  uint64
	Fourth string
}

//creates identifier for each type of CTObject
//Alerts [Subject][Signer][Timestamp][Version]
//The rest [TypeID][Subject|Signer][Timestamp][Version]
func (data *CTObject) Identifier() (ObjectIdentifier){
	if data.TypeID == AlertTypeID{
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
	Major 	uint32	// Major version number
	Minor 	uint32	// Minor version number
	Release uint32	// Release version number
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

// Deconstruct STH from both STH and STHPOC CTObject
func (c *CTObject) DeconstructSTH() (*SignedTreeHeadData, error) {
	var retSTH SignedTreeHeadData
	if c.TypeID == STHTypeID {
		var sth SignedTreeHeadData 
		err := json.Unmarshal(c.Blob, &sth)
		if err != nil {
			return nil, fmt.Errorf("error deconstructing STH from %s CTObject: %v", c.TypeID, err)
		}
		retSTH = sth
	}
	if c.TypeID == STHPOCTypeID {
		sthPOC, err := c.deconstructSTHPOC()
		if err != nil {
			return nil, fmt.Errorf("error deconstructing STH from %s CTObject: %w", c.TypeID, err)
		}
		retSTH = sthPOC.SignedTreeHead
	}
	return &retSTH, nil
}

// Deconstruct POC from STHPOC CTObject
func (c *CTObject) DeconstructPOC() (*ConsistencyProofData, error) {
	sth_poc, err := c.deconstructSTHPOC()
	if err != nil {
		return nil, fmt.Errorf("error deconstructing PoC from %s CTObject: %v", c.TypeID, err)
	}
	return &sth_poc.ConsistencyProof, nil
}

// Deconstruct POC from STHPOC CTObject
func (c *CTObject) deconstructSTHPOC() (*SignedTreeHeadWithConsistencyProof, error) {
	var sth_poc SignedTreeHeadWithConsistencyProof 
	err := json.Unmarshal(c.Blob, &sth_poc)
	if err != nil {
		return nil, fmt.Errorf("error deconstructing STHWithPOC from %s CTObject: %v", c.TypeID, err)
	}
	return &sth_poc, nil
}

// Deconstruct Alert CTObject
func (c *CTObject) DeconstructAlert() (*Alert, error) {
	var alert Alert
	err := json.Unmarshal(c.Blob, &alert)
	if err != nil {
		return nil, fmt.Errorf("error deconstructing Alert from %s CTObject: %w", c.TypeID, err)
	}
	return &alert, nil
}

// Deconstruct AuditOK CTObject
func (c *CTObject) DeconstructSRDAuditOK() (*SRDAuditOK, error) {
	var auditOK SRDAuditOK
	err := json.Unmarshal(c.Blob, &auditOK)
	if err != nil {
		return nil, fmt.Errorf("error deconstructing SRDAuditOK from %s CTObject: %w", c.TypeID, err)
	}
	return &auditOK, nil
}
// Deconstruct AuditOK CTObject
func (c *CTObject) DeconstructSTHAuditOK() (*STHAuditOK, error) {
	var auditOK STHAuditOK
	err := json.Unmarshal(c.Blob, &auditOK)
	if err != nil {
		return nil, fmt.Errorf("error deconstructing STHAuditOK from %s CTObject: %w", c.TypeID, err)
	}
	return &auditOK, nil
}

// Deconstruct ConflictingSTHPOM CTObject
func (c *CTObject) DeconstructConflictingSTHPOM() (*ConflictingSTHPOM, error) {
	var pom ConflictingSTHPOM
	err := json.Unmarshal(c.Blob, &pom)
	if err != nil {
		return nil, fmt.Errorf("error deconstructing ConflictingSTHPOM from %s CTObject: %w", c.TypeID, err)
	}
	return &pom, nil
}

// Deconstruct ConflictingSRDPOM CTObject
func (c *CTObject) DeconstructConflictingSRDPOM() (*ConflictingSRDPOM, error) {
	var pom ConflictingSRDPOM
	err := json.Unmarshal(c.Blob, &pom)
	if err != nil {
		return nil, fmt.Errorf("error deconstructing ConflictingSRDPOM from %s CTObject: %w", c.TypeID, err)
	}
	return &pom, nil
}

// Deconstruct ConflictingSTHPOM CTObject
func (c *CTObject) DeconstructNonRespondingLogPOM() (*NonRespondingLogPOM, error) {
	var pom NonRespondingLogPOM
	err := json.Unmarshal(c.Blob, &pom)
	if err != nil {
		return nil, fmt.Errorf("error deconstructing NonRespondingLogPOM from %s CTObject: %w", c.TypeID, err)
	}
	return &pom, nil
}

func (c *CTObject) deconstructSRDWithRevData() (*SRDWithRevData, error) {
	var srd_rev SRDWithRevData
	err := json.Unmarshal(c.Blob, &srd_rev)
	if err != nil {
		return nil, fmt.Errorf("error deconstructing SRDWithRevData from %s CTObject: %v", c.TypeID, err)
	}
	return &srd_rev, nil
}

func (c *CTObject) DeconstructRevData() (*RevocationData, error) {
	srd_rev, err := c.deconstructSRDWithRevData()
	if err != nil {
		return nil, fmt.Errorf("error deconstructing PoC from %s CTObject: %v", c.TypeID, err)
	}
	return &srd_rev.RevData, nil
}

func (c *CTObject) DeconstructSRD() (*SignedRevocationDigest, error) {
	srd_rev, err := c.deconstructSRDWithRevData()
	if err != nil {
		return nil, fmt.Errorf("error deconstructing PoC from %s CTObject: %v", c.TypeID, err)
	}
	return &srd_rev.SRD, nil
}

// Given a CT v2 Object, construct a CTObject
func ConstructCTObject(i interface{}) (*CTObject, error) {
	var err error
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
		typeID = STHTypeID
		timestamp = sth.TreeHeadData.Timestamp
		signer = sth.LogID
		blob, err = signature.SerializeData(sth)
		if err != nil {
			return nil, fmt.Errorf("error constructing STH CTObject serializing data: %w", err)
		}
		digest, _, err = signature.GenerateHash(sth.Signature.Algorithm.Hash, blob)
		if err != nil {
			return nil, fmt.Errorf("error constructing STH CTObject generating hash: %w", err)
		}
	
	case *Alert:
		alert := i.(*Alert)
		typeID = AlertTypeID
		timestamp = alert.TBS.Timestamp
		signer = alert.TBS.Signer
		blob, err = signature.SerializeData(alert)
		if err != nil {
			return nil, fmt.Errorf("error constructing Alert CTObject serializing data: %w", err)
		}
		digest, _, err = signature.GenerateHash(alert.Signature.Algorithm.Hash, blob)
		if err != nil {
			return nil, fmt.Errorf("error constructing Alert CTObject generating hash: %w", err)
		}
	
	case *SignedTreeHeadWithConsistencyProof:
		sth_poc := i.(*SignedTreeHeadWithConsistencyProof)
		typeID = STHPOCTypeID
		timestamp = sth_poc.SignedTreeHead.TreeHeadData.Timestamp
		signer = sth_poc.SignedTreeHead.LogID
		blob, err = signature.SerializeData(sth_poc)
		if err != nil {
			return nil, fmt.Errorf("error constructing STHPOC CTObject serializing data: %w", err)
		}
		digest, _, err = signature.GenerateHash(sth_poc.SignedTreeHead.Signature.Algorithm.Hash, blob)
		if err != nil {
			return nil, fmt.Errorf("error constructing STHPOC CTObject generating hash: %w", err)
		}
	
	case *SRDWithRevData:
		srd_rev := i.(*SRDWithRevData)
		typeID = SRDWithRevDataTypeID
		timestamp = srd_rev.SRD.RevDigest.Timestamp
		signer = srd_rev.SRD.EntityID
		blob, err = signature.SerializeData(srd_rev)
		if err != nil {
			return nil, fmt.Errorf("error constructing SRDWithRevData CTObject serializing data: %w", err)
		}
		digest, _, err = signature.GenerateHash(srd_rev.SRD.Signature.Algorithm.Hash, blob)
		if err != nil {
			return nil, fmt.Errorf("error constructing SRDWithRevData CTObject generating hash: %w", err)
		}
	
	default:
		return nil, fmt.Errorf("Invalid type: %T", v)
	}

	ctObject := &CTObject{typeID, version, timestamp, signer, subject, digest, blob}
	return ctObject, nil
}

// Given two CtObjects that contain STH, create PoM of conflicting STHs
func CreateConflictingSTHPOM(obj1 *CTObject, obj2 *CTObject) (*CTObject, error) {
	if !(obj1.TypeID == "STH" || obj1.TypeID == "STH_POC") || !(obj2.TypeID == "STH" || obj2.TypeID == "STH_POC"){
		return nil, fmt.Errorf("Not valid STH or STH_POC CTObjects")
	}

	if bytes.Equal(obj1.Digest, obj2.Digest){
		return nil, fmt.Errorf("STHs are not conflicting. Error creating PoM")
	}

	var signer string
	version := VersionData{1,0,0} // TODO replace this with a better way to get currentVersion
	sth1, err := obj1.DeconstructSTH()
	if err != nil {
		return nil, fmt.Errorf("error creating ConflictingSTHPOM: %w", err)
	}

	sth2, err := obj2.DeconstructSTH()
	if err != nil {
		return nil, fmt.Errorf("error creating ConflictingSTHPOM: %w", err)
	}

	// Create fields of the PoM CTObject
	typeID := ConflictingSTHPOMTypeID
	timestamp := sth1.TreeHeadData.Timestamp
	subject := sth1.LogID
	proof := ConflictingSTHPOM{*sth1, *sth2}
	blob, err := signature.SerializeData(proof)
	if err != nil {
		return nil, fmt.Errorf("error constructing ConflictingSTHPOM serializing data: %w", err)
	}
	digest, _, err := signature.GenerateHash(sth1.Signature.Algorithm.Hash, blob)
	if err != nil {
		return nil, fmt.Errorf("error constructing ConflictingSTHPOM generating hash: %w", err)
	}
	
	// Create the POM CTObject
	ctObject := &CTObject{typeID, version, timestamp, signer, subject, digest, blob}
	return ctObject, nil
}

// Given two CtObjects that contain STH, create PoM of conflicting STHs
func CreateConflictingSRDPOM(obj1 *CTObject, obj2 *CTObject) (*CTObject, error) {
	if obj1.TypeID != SRDWithRevDataTypeID || obj2.TypeID != SRDWithRevDataTypeID {
		return nil, fmt.Errorf("Not valid SRDWithRevData CTObjects")
	}

	if bytes.Equal(obj1.Digest, obj2.Digest){
		return nil, fmt.Errorf("SRDs are not conflicting. Error creating PoM")
	}

	var signer string
	version := VersionData{1,0,0} // TODO replace this with a better way to get currentVersion
	srd1, err := obj1.DeconstructSRD()
	if err != nil {
		return nil, fmt.Errorf("error creating ConflictingSTHPOM: %w", err)
	}

	srd2, err := obj2.DeconstructSRD()
	if err != nil {
		return nil, fmt.Errorf("error creating ConflictingSTHPOM: %w", err)
	}

	// Create fields of the PoM CTObject
	typeID := ConflictingSRDPOMTypeID
	timestamp := srd1.RevDigest.Timestamp
	subject := srd1.EntityID
	proof := ConflictingSRDPOM{*srd1, *srd2}
	blob, err := signature.SerializeData(proof)
	if err != nil {
		return nil, fmt.Errorf("error constructing ConflictingSRDPOM serializing data: %w", err)
	}
	digest, _, err := signature.GenerateHash(srd1.Signature.Algorithm.Hash, blob)
	if err != nil {
		return nil, fmt.Errorf("error constructing ConflictingSRDPOM generating hash: %w", err)
	}
	
	// Create the POM CTObject
	ctObject := &CTObject{typeID, version, timestamp, signer, subject, digest, blob}
	return ctObject, nil
}

// Given signer and sth ctobject, create AuditOK
func CreateSTHAuditOK(sigSigner *signature.Signer, sthCT *CTObject) (*CTObject, error){
	var signer string
	version := VersionData{1,0,0}
	sth, err := sthCT.DeconstructSTH()
	if err != nil {
		return nil, fmt.Errorf("error creating AuditOK: %w", err)
	}

	// Create fields of AuditOk CTbject
	typeID := STHAuditOKTypeID
	timestamp := sth.TreeHeadData.Timestamp
	subject := sth.LogID

	// Sign the STH and create the AuditOK
	sig, err := sigSigner.CreateSignature(tls.SHA256, sth)
	auditOK := AuditOK{*sth, *sig}
	blob, err := signature.SerializeData(auditOK)
	if err != nil {
		return nil, fmt.Errorf("error constructing AuditOK serializing data: %w", err)
	}
	digest, _, err := signature.GenerateHash(sth.Signature.Algorithm.Hash, blob)
	if err != nil {
		return nil, fmt.Errorf("error constructing AuditOK generating hash: %w", err)
	}
	
	// Create the CTObject PoM
	ctObject := &CTObject{typeID, version, timestamp, signer, subject, digest, blob}
	return ctObject, nil
}

// Given signer and srdWithRevData ctobject, create AuditOK
func CreateSRDAuditOK(sigSigner *signature.Signer, srdCT *CTObject) (*CTObject, error){
	var signer string
	version := VersionData{1,0,0}
	srd, err := srdCT.DeconstructSRD()
	if err != nil {
		return nil, fmt.Errorf("error creating SRD AuditOK: %w", err)
	}

	// Create fields of AuditOk CTbject
	typeID := SRDAuditOKTypeID
	timestamp := srd.RevDigest.Timestamp
	subject := srd.EntityID

	// Sign the STH and create the AuditOK
	sig, err := sigSigner.CreateSignature(tls.SHA256, srd)
	auditOK := SRDAuditOK{*srd, *sig}
	blob, err := signature.SerializeData(auditOK)
	if err != nil {
		return nil, fmt.Errorf("error constructing AuditOK serializing data: %w", err)
	}
	digest, _, err := signature.GenerateHash(srd.Signature.Algorithm.Hash, blob)
	if err != nil {
		return nil, fmt.Errorf("error constructing AuditOK generating hash: %w", err)
	}
	
	// Create the CTObject PoM
	ctObject := &CTObject{typeID, version, timestamp, signer, subject, digest, blob}
	return ctObject, nil
}