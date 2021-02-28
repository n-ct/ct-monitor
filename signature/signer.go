package signature

import (
	"crypto"
	"encoding/base64"
	"crypto/ecdsa"

	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	ct "github.com/google/certificate-transparency-go"
)

type Signer struct {
	PrivKey crypto.PrivateKey
}

// TODO fix the error return
// TODO Also add support for non ECDSA keys in the future
func NewSigner(privKey string) *Signer{
	derPrivKey, _ := base64.StdEncoding.DecodeString(privKey)
	privateKey, _ := x509.ParseECPrivateKey(derPrivKey)
	signer := &Signer{privateKey}
	return signer
}

// TODO add if statements to handle errors
func (s *Signer) CreateSignature(hashAlgo tls.HashAlgorithm, toBeSigned interface{}) (ct.DigitallySigned, error){
	data, err := SerializeData(toBeSigned)
	sig, err := tls.CreateSignature(*s.PrivKey.(*ecdsa.PrivateKey), hashAlgo, data)
	return ct.DigitallySigned(sig), err
}