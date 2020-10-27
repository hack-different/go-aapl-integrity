package img4

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

const (
	Image4TypeBare = 0
	Image4TypeComplete = 1
	Image4TypePayload = 2
	Image4TypeManifest = 3

	Image4MagicComplete = "IMG4"
	Image4MagicPayload = "IM4P"
	Image4MagicManifest = "IM4M"
)

type Image4 struct {
	Payload *Image4Payload
	Manifest *Image4Manifest
}

type Image4KeyBagItem struct {
	Index int
	Key string
	Value []byte
}

type Image4Payload struct {
	Name string
	Description string
	Data []byte
	KeyBag []*Image4KeyBagItem
}

type Image4Manifest struct {
	Version int

	Signature []byte
	Certificates []*x509.Certificate
}

func parsePayload(data []interface{}) (*Image4Payload, error) {

}

func parse(data []byte) (*Image4, error) {
	root := make([]interface{}, 0)
	result := &Image4{}

	_, err := asn1.Unmarshal(data, root)
	if err != nil { return nil, err }

	magic, ok := root[0].(string)
	if ok == false {
		return nil, fmt.Errorf("invalid data, no magic (maybe bare?)")
	}

	switch magic {
	case Image4MagicComplete:

	case Image4MagicManifest:

	case Image4MagicPayload:

	default:
		return nil, fmt.Errorf("unknown magic %s", magic)
	}

	return result, nil
}