package signature

import (
	"testing"
	"bytes"
	"encoding/json"

	"github.com/google/certificate-transparency-go/tls"
)

var (
	testValidECDSAPrivKey = "MHcCAQEEIDMTSq99YDvC5TfMoY+0jt4ruExuMifqrjOisWBds1yNoAoGCCqGSM49AwEHoUQDQgAE2HQc8jcuoOj/H/4+HQItNBEolurr547rC5i4O61Wf0mxvV9anHz+kIcTy7n9hnStoK+WGkI3fF6k7l2IO3OiyA=="
	testValidECDSAPubKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2HQc8jcuoOj/H/4+HQItNBEolurr547rC5i4O61Wf0mxvV9anHz+kIcTy7n9hnStoK+WGkI3fF6k7l2IO3OiyA=="
	testString = "Sign this"
	testInt = 10
)

func mustCreateSigner(t *testing.T, strPrivKey string) (*Signer, error) {
	t.Helper()
	return NewSigner(strPrivKey)
}

func TestNewSigner(t *testing.T) {
	_, err := mustCreateSigner(t, testValidECDSAPrivKey)
	if err != nil {
		t.Fatalf("NewSigner failed with privKey (%v): %v", testValidECDSAPrivKey, err)
	}
}

func TestCreateSignatureVerifySignatureRoundTrip(t *testing.T) {
	tests := []struct {
		privKey 	string
		pubKey  	string
		hashAlg 	tls.HashAlgorithm
		toBeSigned 	interface{}
	} {
		{
			privKey: testValidECDSAPrivKey,
			pubKey: testValidECDSAPubKey,
			hashAlg: tls.SHA256,
			toBeSigned: testString,
		},
		{
			privKey: testValidECDSAPrivKey,
			pubKey: testValidECDSAPubKey,
			hashAlg: tls.SHA256,
			toBeSigned: testInt,
		},
	}

	for _, test := range tests {
		signer, _ := mustCreateSigner(t, test.privKey)
		sig, err := signer.CreateSignature(test.hashAlg, test.toBeSigned)
		if err != nil {
			t.Errorf("CreateSignature failed with privKey (%v) and pubKey (%v): %v", test.privKey, test.pubKey, err)
		}

		if VerifySignature(test.pubKey, test.toBeSigned, *sig) != nil {
			t.Errorf("VerifySignature failed with pubKey (%v), dataTBS (%v), and signature (%v)", test.pubKey, test.toBeSigned, *sig)
		}
	}
}

func TestSerializeData(t *testing.T) {
	testBytes, _ := json.Marshal(testString)
	serializedData, err := SerializeData(testString)
	if err != nil {
		t.Errorf("failed to serialize data (%v): %v", testString, err)
	}

	if !bytes.Equal(testBytes, serializedData) {
		t.Errorf("mismatching SerializedData (%v) and testBytes(%v)", serializedData, testBytes)
	}
}

func TestGenerateHash(t *testing.T) {
	serializedData, _ := SerializeData(testString)
	_, _, err := GenerateHash(tls.SHA256, serializedData)
	if err != nil {
		t.Errorf("failed to generateHash with hashalg(%v) and data (%v): %v", tls.SHA256, serializedData, err)
	}
}
