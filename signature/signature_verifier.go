package signature

import (
	"crypto"
	"fmt"
	"encoding/json"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
)

// VerifySignature verifies that the passed in signature over data was created by the given PublicKey.
func VerifySignature(strPubKey string, data interface{}, sig ct.DigitallySigned) error {
	pubKey, err := ct.PublicKeyFromB64(strPubKey)
	byteData, err := SerializeData(data)
	err = tls.VerifySignature(pubKey, byteData, tls.DigitallySigned(sig))
	return err
}

func SerializeData(i interface{}) ([]byte, error) {
	switch i.(type) {
	case ct.TreeHeadSignature:
		return tls.Marshal(i)
	default:
		return json.Marshal(i)
	}
}

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
		return nil, hashType, fmt.Errorf("unsupported Algorithm.Hash in signature: %v", algo)
	}

	hasher := hashType.New()
	if _, err := hasher.Write(data); err != nil {
		return nil, hashType, fmt.Errorf("failed to write to hasher: %v", err)
	}
	return hasher.Sum([]byte{}), hashType, nil
}
