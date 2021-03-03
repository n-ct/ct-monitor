package signature

import (
	"fmt"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"

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

// VerifySignature verifies that the passed in signature over data was created by the given PublicKey.
// If the signature is valid, function will return nil
func VerifySignature(strPubKey string, data interface{}, sig ct.DigitallySigned) error {
	pubKey, err := ct.PublicKeyFromB64(strPubKey)
	if err != nil {
		return fmt.Errorf("error parsing string PublicKey for signature verification: %w", err)
	}
	byteData, err := SerializeData(data)
	if err != nil {
		return fmt.Errorf("error serializing %T type struct for signature verification: %w", data, err)
	}
	err = tls.VerifySignature(pubKey, byteData, tls.DigitallySigned(sig))
	return err
}

// SerializeData converts the given object into a byte array
// CertificateTransparencyGo repository signed objects are Marshaled in their own way
func SerializeData(i interface{}) (byteArr []byte, err error) {
	switch i.(type) {
	case ct.TreeHeadSignature:
		byteArr, err = tls.Marshal(i)
		if err != nil {
			return byteArr, fmt.Errorf("error certificate-transparency-go serializing %T type struct: %w", i, err)
		}
	default:
		byteArr, err = json.Marshal(i)
		if err != nil {
			return byteArr, fmt.Errorf("error serializing %T type struct: %v", i, err)
		}
	}
	return byteArr, nil
}

// GenerateHash produces the hash of the given data.
// The Algorithm is of type HashAlgorithm, which is found in certificate-transparency-go/tls package
func GenerateHash(algo tls.HashAlgorithm, data []byte) ([]byte, crypto.Hash, error) {
	var hashType crypto.Hash
	switch algo {
	case tls.MD5:
		hashType = crypto.MD5
	case tls.SHA1:
		hashType = crypto.SHA1
	case tls.SHA224:
		hashType = crypto.SHA224
	case tls.SHA256:
		hashType = crypto.SHA256
	case tls.SHA384:
		hashType = crypto.SHA384
	case tls.SHA512:
		hashType = crypto.SHA512
	default:
		return nil, hashType, fmt.Errorf("unsupported Algorithm.Hash: %v", algo)
	}

	hasher := hashType.New()
	if _, err := hasher.Write(data); err != nil {
		return nil, hashType, fmt.Errorf("failed to write to hasher: %v", err)
	}
	return hasher.Sum([]byte{}), hashType, nil
}