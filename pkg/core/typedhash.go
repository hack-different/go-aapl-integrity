package core

import (
	"bytes"
	"fmt"
)

const (
	HashSHA1 = 1
	HashSHA1Size = 20
	HashSHA256 = 2
	HashSHA256Size = 32
	HashSHA256Truncated = 3 // First 20 bytes of a SHA256
	HashSHA256TruncatedSize = 20
	HashSHA384 = 4
	HashSHA384Size = 48
)

type TypedHash struct {
	Type int
	Data []byte
}

func (th TypedHash) size() int {
	switch th.Type {
	case HashSHA256:
		return 32
	case HashSHA384:
		return 48
	case HashSHA1:
	case HashSHA256Truncated:
		return 20
	}

	return 20
}

func (th *TypedHash) toSHA256Truncated() (*TypedHash, error) {
	if th.Type == HashSHA256Truncated {
		return th, nil
	}

	if th.Type == HashSHA256 {
		return &TypedHash{
			Type: HashSHA256Truncated,
			Data: th.Data[0:HashSHA1Size],
		}, nil
	}

	return nil, fmt.Errorf("cannot truncate unrelated hash type %d", th.Type)
}

func (th *TypedHash) equalTo(other *TypedHash) (bool, error) {
	if th.Type == HashSHA256Truncated || other.Type == HashSHA256Truncated {
		thTruncated, err := th.toSHA256Truncated()
		if err != nil {
			return false, err
		}

		otherTruncated, err := other.toSHA256Truncated()
		if err != nil {
			return false, err
		}

		return thTruncated.equalTo(otherTruncated)
	}

	if th.Type != other.Type {
		return false, fmt.Errorf("type %d does not match type %d", th.Type, other.Type)
	}

	if len(th.Data) != len(other.Data) {
		return false, fmt.Errorf("length %d does not match length %d", len(th.Data), len(other.Data))
	}

	return bytes.Equal(th.Data, other.Data), nil
}