package signature

import (
	"crypto"
	"github.com/google/certificate-transparency-go/tls"
	ct "github.com/google/certificate-transparency-go"
)

type Signer struct {
	PrivKey crypto.PrivateKey
}

// TODO need to find a way to convert a string priv key to crypto.PrivateKey
/*func NewSigner(privKey string) *Signer{
	
}
*/

func (s *Signer) CreateSignature(hashAlgo tls.HashAlgorithm, data []byte) (ct.DigitallySigned, error){
	sig, err := tls.CreateSignature(s.PrivKey, hashAlgo, data)
	return ct.DigitallySigned(sig), err
}