package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/google/uuid"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const ChunklistMagic = 0x4C4B4E43
const ChunklistFileVersion10 = 1
const ChunklistChunkMethod10 = 1
const ChunklistSignatureMethodRev1 = 1
const ChunklistSignatureMethodIntegrityData = 2
const ChunklistSignatureMethodRev2 = 3
const ChunklistRev1SigLen = 256
const ChunklistRev2SigLen = 808
const ChunklistPubkeyLen = 2048/8
const ChunklistSignatureLen = 2048/8
const Sha256DigestLength = 32
const HashBufferSize = 1024 * 32

type chunklistSignature interface {
	verify(bytes []uint8) error
}

type Chunklist struct {
	magic       	uint32
	headerSize  	uint32
  	fileVersion 	uint8
  	chunkMethod 	uint8
  	signatureMethod uint8
 	chunkCount  	uint64
 	chunkOffset 	uint64
 	signatureOffset uint64
	chunks			[]ChunklistChunk
	signature		chunklistSignature
}

type ChunklistChunk struct {
	chunkSize uint32
  	chunkHash []byte
}

type ChunklistCertificate struct {
 	length          uint32
  	revision        uint8
  	securityEpoch   uint8
 	certificateType uint16
   	certificateGuid uuid.UUID
   	hashTypeGuid    uuid.UUID
  	rsaPublicKey    [ChunklistPubkeyLen]byte
  	rsaSignature    [ChunklistSignatureLen]byte
}

type ChunklistPubkey struct {
	isProduction bool
	key          [ChunklistPubkeyLen]byte
}

func readChunklistPublicKey(file *os.File) (*ChunklistPubkey, error) {
	return new(ChunklistPubkey), nil
}

func readChunklist(file *os.File) (*Chunklist, error) {
	result := new(Chunklist)
	var unused uint8
	binary.Read(file, binary.LittleEndian, &result.magic)

	if result.magic != ChunklistMagic {
		return nil, fmt.Errorf("bad magic %X", result.magic)
	}

	binary.Read(file, binary.LittleEndian, &result.headerSize)
	binary.Read(file, binary.LittleEndian, &result.fileVersion)
	if result.fileVersion != ChunklistFileVersion10 {
		return nil, fmt.Errorf("unsupported version %d", result.fileVersion)
	}

	binary.Read(file, binary.LittleEndian, &result.chunkMethod)
	if result.chunkMethod != ChunklistChunkMethod10 {
		return nil, fmt.Errorf("unsupported chunk method %d", result.chunkMethod)
	}

	binary.Read(file, binary.LittleEndian, &result.signatureMethod)
	if result.signatureMethod != ChunklistSignatureMethodRev1 {
		return nil, fmt.Errorf("unsupported signature method %d", result.signatureMethod)
	}

	binary.Read(file, binary.LittleEndian, &unused)
	binary.Read(file, binary.LittleEndian, &result.chunkCount)
	binary.Read(file, binary.LittleEndian, &result.chunkOffset)
	binary.Read(file, binary.LittleEndian, &result.signatureOffset)

	result.chunks = make([]ChunklistChunk, result.chunkCount)
	file.Seek(int64(result.chunkOffset), io.SeekStart)
	for index, _ := range result.chunks {
		binary.Read(file, binary.LittleEndian, &result.chunks[index].chunkSize)
		result.chunks[index].chunkHash = make([]byte, Sha256DigestLength)
		file.Read(result.chunks[index].chunkHash)
	}

	file.Seek(int64(result.signatureOffset), io.SeekStart)
	switch result.signatureMethod {
	case ChunklistSignatureMethodRev1:
		result.signature, _ = readChunklistPublicKey(file)
	}

	return result, nil
}

func hashBytes(file *os.File, length uint32) []byte {
	hasher := sha256.New()
	buffer := make([]byte, HashBufferSize)
	hasher.Reset()

	// NOTE: Special case handling.  0 = remainder of file
	if length == 0 {
		fi, _ := file.Stat()
		location, _ := file.Seek(0, io.SeekCurrent)
		length = uint32(fi.Size() - location)
	}

	for length > 0 {
		count, _ := file.Read(buffer)
		hasher.Write(buffer[:count])
		length -= uint32(count)
	}

	return hasher.Sum([]byte{})
}

func (cl *Chunklist) verify(file *os.File) []error {
	errors := make([]error, 0)

	file.Seek(0, io.SeekStart)

	// TODO: Provide bytes to verify
	err := cl.signature.verify([]byte{})
	if err != nil {
		return []error { err }
	}

	for index, chunk := range cl.chunks {
		result := hashBytes(file, chunk.chunkSize)
		if !bytes.Equal(result, chunk.chunkHash[:]) {
			errors = append(errors, fmt.Errorf("invalid chunk %d", index))
		}
	}

	return errors
}

func (key ChunklistPubkey) verify(bytes []uint8) error {
	// TODO: verify public key
	return nil
}

func (certificate ChunklistCertificate) verify(bytes []uint8) error {
	// TODO: verify certificate
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Print("File is required")
		os.Exit(-1)
	}

	_, err := os.Stat(os.Args[1])
	if os.IsExist(err) {
		fmt.Printf("File %s does not exist or it cannot be read", os.Args[1])
		os.Exit(-2)
	}

	ext := filepath.Ext(os.Args[1])
	if ext == "chunklist" {
		fmt.Print("Specify the name of the file to verify, not the chunklist\n")
		os.Exit(-3)
	}

	chunklistPath := fmt.Sprintf("%s.chunklist", strings.TrimSuffix(os.Args[1], ext))
	_, err = os.Stat(chunklistPath)
	if os.IsExist(err) {
		fmt.Printf("Chunklist file %s does not exist\n", chunklistPath)
		os.Exit(-4)
	}

	chunklistFile, err := os.Open(chunklistPath)
	if err != nil {
		fmt.Printf("Could not open file %s\n", chunklistPath)
		os.Exit(-5)
	}

	chunklist, err := readChunklist(chunklistFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(-6)
	}

	targetFile, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Println(err)
		os.Exit(-7)
	}

	fmt.Printf("Verifying %d chunks\n", chunklist.chunkCount)
	verificationErrors := chunklist.verify(targetFile)
	if len(verificationErrors) == 0 {
		fmt.Print("File verification successful\n")
		os.Exit(0)
	}

	for _, err = range verificationErrors {
		fmt.Println(err)
	}
	os.Exit(len(verificationErrors))
}
