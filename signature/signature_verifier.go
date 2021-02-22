package signature

import (
	"encoding/json"
	"github.com/google/certificate-transparency-go/tls"
	ct "github.com/google/certificate-transparency-go"
)

// VerifySignature verifies that the passed in signature over data was created by the given PublicKey.
func VerifySignature(strPubKey string, i interface{}, sig ct.DigitallySigned) error {
	data, err := SerializeData(i)
	pubKey, err := ct.PublicKeyFromB64(strPubKey)
	err = tls.VerifySignature(pubKey, data, tls.DigitallySigned(sig))
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