package mtr

import (
	"testing"
	"reflect"

	"github.com/n-ct/ct-monitor/signature"
	ct "github.com/google/certificate-transparency-go"
)

var (
	testValidECDSAPrivKey = "MHcCAQEEIDMTSq99YDvC5TfMoY+0jt4ruExuMifqrjOisWBds1yNoAoGCCqGSM49AwEHoUQDQgAE2HQc8jcuoOj/H/4+HQItNBEolurr547rC5i4O61Wf0mxvV9anHz+kIcTy7n9hnStoK+WGkI3fF6k7l2IO3OiyA=="
)

func TestSTHIdentifier(t *testing.T) {
	// For now will just have STH test
	// Will possibly separate the identifer into a separate class
	sth, err := mustGetSTH(t)
	if err != nil {
		t.Fatalf("failed to get sth to test identifier: %v", err)
	}
	expectedSTHIdentifer := ObjectIdentifier{First: sth.TypeID, Second: sth.Signer, Third: sth.Timestamp, Fourth: sth.Version.String(),}
	sthIdentifier := sth.Identifier()
	if expectedSTHIdentifer != sthIdentifier {
		t.Fatalf("identifier of sth (%v) doesn't match expected identifer (%v)", sthIdentifier, expectedSTHIdentifer)
	}
}

func TestVersionDataString(t *testing.T) {
	testVersionData := VersionData{Major: 1, Minor: 2, Release: 1}
	expectedVersionDataString := "1.2"
	versionDataString := testVersionData.String()
	if expectedVersionDataString != versionDataString {
		t.Fatalf("test versionDataString (%v) doesn't match expectedversionDataString (%v)", versionDataString, expectedVersionDataString)
	}
}

func TestDeconstructConstructSTHRoundTrip(t *testing.T) {
	sth, err := mustGetSTH(t)
	if err != nil {
		t.Fatalf("failed to get sth to test deconstructConstructRoundTrip: %v", err)
	}
	deconSTH, err := sth.DeconstructSTH()
	if err != nil {
		t.Fatalf("failed to deconstruct sth (%v): %v", sth, err)
	}
	reconSTH, err := ConstructCTObject(deconSTH)
	if err != nil {
		t.Fatalf("failed to reconstruct deconstructed sth (%v): %v", deconSTH, err)
	}
	
	if !reflect.DeepEqual(reconSTH, sth) {
		t.Fatalf("reconstructed sth\n(%v) doesn't match original sth\n(%v)", reconSTH, sth)
	}
}

func TestDeconstructConstructPOCRoundTrip(t *testing.T) {
	validFirstTreeSize := uint64(100)
	validSecondTreeSize := uint64(1000)
	sthpoc, err := mustGetSTHWithConsistencyProof(t, validFirstTreeSize, validSecondTreeSize)
	if err != nil {
		t.Fatalf("failed to get sthpoc to test deconstructConstructRoundTrip: %v", err)
	}
	deconSTH, err := sthpoc.DeconstructSTH()
	if err != nil {
		t.Fatalf("failed to deconstruct sthpoc (%v): %v", sthpoc, err)
	}
	deconPOC, err := sthpoc.DeconstructPOC()
	if err != nil {
		t.Fatalf("failed to deconstruct sthpoc (%v): %v", sthpoc, err)
	}
	newSTHPOC := &SignedTreeHeadWithConsistencyProof{SignedTreeHead: *deconSTH, ConsistencyProof: *deconPOC}
	reconSTHPOC, err := ConstructCTObject(newSTHPOC)
	if err != nil {
		t.Fatalf("failed to reconstruct deconstructed sthpoc (%v): %v", newSTHPOC, err)
	}
	
	if !reflect.DeepEqual(reconSTHPOC, sthpoc) {
		t.Fatalf("reconstructed sthPOC\n(%v) doesn't match original sthPOC\n (%v)", reconSTHPOC, sthpoc)
	}
}

func mustCreateSTHCopyWithDifferentHash(t *testing.T, sth *CTObject) *CTObject {
	t.Helper()
	newDigest := sth.Digest[1:]
	newSTH := &CTObject{sth.TypeID, sth.Version, sth.Timestamp, sth.Signer, sth.Subject, newDigest, sth.Blob}
	return newSTH
}

func TestCreateDeconstructSTHPOMRoundTrip(t *testing.T) {
	sth1, err := mustGetSTH(t)
	if err != nil {
		t.Fatalf("failed to get sth to test deconstructConstructSTHPOMRoundTrip: %v", err)
	}
	sth2 := mustCreateSTHCopyWithDifferentHash(t, sth1)
	sthpom, err := CreateConflictingSTHPOM(sth1, sth2)
	if err != nil {
		t.Fatalf("failed to create ConflictingSTHPOM: %v", err)
	}
	deconSTHPOM, err := sthpom.DeconstructConflictingSTHPOM()
	if err != nil {
		t.Fatalf("failed to deconstruct ConflictingSTHPOM: %v", err)
	}
	deconSTH1, err := sth1.DeconstructSTH()
	if err != nil {
		t.Fatalf("failed to deconstruct STH: %v", err)
	}
	deconSTH2, err := sth2.DeconstructSTH()
	if err != nil {
		t.Fatalf("failed to deconstruct STH: %v", err)
	}
	newSTHPOM := ConflictingSTHPOM{*deconSTH1, *deconSTH2}
	if !reflect.DeepEqual(newSTHPOM, *deconSTHPOM) {
		t.Fatalf("reconstructed ConflictingSTHPOM\n(%v) doesn't match original ConflictingSTHPOM\n (%v)", newSTHPOM, *deconSTHPOM)
	}
}
func mustCreateSigner(t *testing.T, strPrivKey string) (*signature.Signer, error) {
	t.Helper()
	return signature.NewSigner(strPrivKey)
}

func TestCreateDeconstructSTHAuditOKRoundTrip(t *testing.T) {
	signer, err := mustCreateSigner(t, testValidECDSAPrivKey)
	if err != nil {
		t.Fatalf("failed to construct signature to test auditOK: %v", err)	
	}
	sth, err := mustGetSTH(t)
	if err != nil {
		t.Fatalf("failed to get sth to test auditOK: %v", err)
	}
	auditOK, err := CreateSTHAuditOK(signer, sth)
	if err != nil {
		t.Fatalf("failed to create auditOK: %v", err)
	}
	deconAuditOK, err := auditOK.DeconstructSTHAuditOK()
	if err != nil {
		t.Fatalf("failed to deconstruct auditOK: %v", err)
	}
	reconSTH, err := ConstructCTObject(&deconAuditOK.STH)
	if err != nil {
		t.Fatalf("failed to reconstruct deconstructed auditOKSTH: %v", err)
	}
	
	if !reflect.DeepEqual(reconSTH, sth) {
		t.Fatalf("reconstructed AuditOKSTH \n(%v) doesn't match original sth\n (%v)", reconSTH, sth)
	}
}

func mustCreateSRD(t *testing.T, sig ct.DigitallySigned) (*SignedRevocationDigest) {
	hsh := []byte("hi")
	revDigest := RevocationDigest{3, hsh, hsh}
	srd := SignedRevocationDigest{"ca", revDigest, sig}
	return &srd
}

func TestConstructDeconstructSRDRoundTrip(t *testing.T) {
	sth, err := mustGetSTH(t)
	if err != nil {
		t.Fatalf("failed to get sth to test deconstructConstructRoundTrip: %v", err)
	}
	deconSTH, err := sth.DeconstructSTH()
	if err != nil {
		t.Fatalf("failed to deconstruct sth (%v): %v", sth, err)
	}
	baseSRD := mustCreateSRD(t, deconSTH.Signature)
	constrSRD, err := ConstructCTObject(baseSRD)
	if err != nil {
		t.Fatalf("failed to construct SRD (%v): %v", constrSRD, err)
	}
	deconSRD, err := constrSRD.DeconstructSRD()
	if err != nil {
		t.Fatalf("failed to deconstruct srd (%v): %v", constrSRD, err)
	}

	if !reflect.DeepEqual(baseSRD, deconSRD) {
		t.Fatalf("deconstructed srd\n(%v) doesn't match original srd\n (%v)", deconSRD, baseSRD)
	}
}