package signature

import (
	"fmt"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
)

type Signer struct {
	PrivKey crypto.PrivateKey
}

// TODO Also add support for non ECDSA keys in the future
// Create a NewSigner with ECDSA PrivateKey
func NewSigner(privKey string) (*Signer, error){
	derPrivKey, err := base64.StdEncoding.DecodeString(privKey)
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding private key for new signer: %w", err)
	}
	privateKey, err := x509.ParseECPrivateKey(derPrivKey)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key for new signer: %w", err)
	}
	signer := &Signer{privateKey}
	return signer, nil
}

// Create Signature of given certificate-transparency-go/tls package defined hash algorithm and object to be signed
func (s *Signer) CreateSignature(hashAlgo tls.HashAlgorithm, toBeSigned interface{}) (*ct.DigitallySigned, error){
	data, err := SerializeData(toBeSigned)
	if err != nil {
		return nil, fmt.Errorf("error creating signature: %w", err)
	}
	sig, err := tls.CreateSignature(*s.PrivKey.(*ecdsa.PrivateKey), hashAlgo, data)
	digSig := ct.DigitallySigned(sig)
	return &digSig, err
}