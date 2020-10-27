package trustcache

import (
	"fmt"
	"github.com/google/uuid"
	"go-aapl-integrity/pkg/core"
	"encoding/binary"
)

const (
	TrustCacheV0 = 0
	TrustCacheV0HeaderSize = 24
	TrustCacheV0EntrySize = core.HashSHA1Size
	TrustCacheV1 = 1
	TrustCacheV1HeaderSize = 24
	TrustCacheV1EntrySize = core.HashSHA1Size + 2

	HashLength = 20

	FlagAMFI = 0x01
)

type Entry interface {
	getHash() *core.TypedHash
	getType() int
	getFlags() int
}

type TrustCache struct {
	Version uint32
	UUID uuid.UUID
	Count uint32
	Entries []Entry
}

type Rev0Entry struct {
	HashData [HashLength]byte
}

func (entry Rev0Entry) getHash() *core.TypedHash {
	return &core.TypedHash{
		Type: core.HashSHA1,
		Data: entry.HashData[:],
	}
}

type Rev1Entry struct {
	HashData [HashLength]byte
	HashType uint8
	Flags uint8
}

func (entry Rev1Entry) getHash() *core.TypedHash {
	return &core.TypedHash{
		Type: int(entry.HashType),
		Data: entry.HashData[:],
	}
}

func (entry Rev0Entry) getType() int {
	return core.HashSHA1
}

func (entry Rev0Entry) getFlags() int {
	return FlagAMFI
}

func (entry Rev1Entry) getType() int {
	return int(entry.HashType)
}

func (entry Rev1Entry) getFlags() int {
	return int(entry.Flags)
}

func parse(data []byte) (*TrustCache, error) {
	if len(data) < 24 { return nil, fmt.Errorf("not enough data for header") }

	version := binary.LittleEndian.Uint32(data[0:4])
	count := binary.LittleEndian.Uint32(data[20:24])

	uuid, err := uuid.FromBytes(data[4:20])
	if err != nil { return nil, err }

	entries := make([]Entry, count)

	switch version {
	case TrustCacheV0:
		expectedSize := int(TrustCacheV0HeaderSize + (count * TrustCacheV0EntrySize))
		if len(data) != expectedSize {
			return nil, fmt.Errorf("data size %d does not match expected size %d", len(data), expectedSize)
		}

		for index, _ := range entries {
			start := TrustCacheV0HeaderSize + (index * TrustCacheV0EntrySize)

			entry := &Rev0Entry{}

			copy(entry.HashData[:], data[start:(start + TrustCacheV0EntrySize)])

			entries[index] = entry
		}

	case TrustCacheV1:
		expectedSize := int(TrustCacheV1HeaderSize + (count * TrustCacheV1EntrySize))
		if len(data) != expectedSize {
			return nil, fmt.Errorf("data size %d does not match expected size %d", len(data), expectedSize)
		}

		for index, _ := range entries {
			start := TrustCacheV1HeaderSize + (index * TrustCacheV1EntrySize)

			entry := &Rev1Entry{
				HashType: data[(start + core.HashSHA1Size)],
				Flags: data[(start + core.HashSHA1Size + 1)],
			}

			copy(entry.HashData[:], data[start:(start + core.HashSHA1Size)])

			entries[index] = entry
		}

	default:
		return nil, fmt.Errorf("invalid trustcache version %d", version)
	}

	return &TrustCache{
		Version: version,
		UUID:    uuid,
		Count:   count,
		Entries: entries,
	}, nil
}