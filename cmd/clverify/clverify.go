package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
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
const ChunklistPubkeyExp = 0x010001
const ChunklistSignatureLen = 2048/8
const Sha256DigestLength = 32
const HashBufferSize = 1024 * 32


type chunklistSignature interface {
	verify(bytes []uint8) error
}

type chunklist struct {
	magic       	uint32
	headerSize  	uint32
  	fileVersion 	uint8
  	chunkMethod 	uint8
  	signatureMethod uint8
 	chunkCount  	uint64
 	chunkOffset 	uint64
 	signatureOffset uint64
	chunks			[]chunklistChunk
	signature		chunklistSignature
}

type chunklistChunk struct {
	chunkSize uint32
  	chunkHash []byte
}

type chunklistCertificate struct {
 	length          uint32
  	revision        uint8
  	securityEpoch   uint8
 	certificateType uint16
   	certificateGuid uuid.UUID
   	hashTypeGuid    uuid.UUID
  	rsaPublicKey    [ChunklistPubkeyLen]byte
  	rsaSignature    [ChunklistSignatureLen]byte
}

type chunklistPubkey struct {
	signature []byte
	validKeys []*rsa.PublicKey
}

func readPublicKey() (*rsa.PublicKey, error) {
	file, err := os.Open("keys.pem")
	if err != nil {
		return nil, err
	}

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}

	publicKeyData := make([]byte, fileInfo.Size())
	count, err := file.Read(publicKeyData)
	if int64(count) != fileInfo.Size() {
		err = fmt.Errorf("could not read entire file")
	}
	if err != nil {
		return nil, err
	}

	publicKey, _ := pem.Decode(publicKeyData)

	return x509.ParsePKCS1PublicKey(publicKey.Bytes)
}

func readChunklistPublicKey(file *os.File) (*chunklistPubkey, error) {
	result := new(chunklistPubkey)

	result.validKeys = make([]*rsa.PublicKey, 1)
	key, err := readPublicKey()
	if err != nil {
		return nil, err
	}
	result.validKeys[0] = key

	result.signature = make([]byte, ChunklistPubkeyLen)
	count, err := file.Read(result.signature)
	if count != ChunklistPubkeyLen {
		err = fmt.Errorf("public key is invalid size %d", count)
	}
	if err != nil {
		return nil, err
	}

	return result, nil
}

func readChunklist(file *os.File) (*chunklist, error) {
	result := new(chunklist)
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

	result.chunks = make([]chunklistChunk, result.chunkCount)
	file.Seek(int64(result.chunkOffset), io.SeekStart)
	for index := range result.chunks {
		binary.Read(file, binary.LittleEndian, &result.chunks[index].chunkSize)
		result.chunks[index].chunkHash = make([]byte, Sha256DigestLength)
		file.Read(result.chunks[index].chunkHash)
	}

	file.Seek(int64(result.signatureOffset), io.SeekStart)
	var err error
	switch result.signatureMethod {
	case ChunklistSignatureMethodRev1:
		result.signature, err = readChunklistPublicKey(file)
	}
	if err != nil {
		return nil, err
	}

	return result, nil
}

func hashFile(file *os.File, length uint32) []byte {
	hash := sha256.New()
	buffer := make([]byte, HashBufferSize)
	hash.Reset()

	// NOTE: Special case handling.  0 = remainder of file
	if length == 0 {
		fi, _ := file.Stat()
		location, _ := file.Seek(0, io.SeekCurrent)
		length = uint32(fi.Size() - location)
	}

	for length > 0 {
		count, _ := file.Read(buffer)
		hash.Write(buffer[:count])
		length -= uint32(count)
	}

	return hash.Sum([]byte{})
}

func (cl *chunklist) verify(file *os.File) []error {
	errors := make([]error, 0)

	file.Seek(0, io.SeekStart)

	signedBytes := make([]byte, cl.signatureOffset)
	file.Read(signedBytes)

	err := cl.signature.verify(signedBytes)
	if err != nil {
		return []error { err }
	}

	for index, chunk := range cl.chunks {
		result := hashFile(file, chunk.chunkSize)
		if !bytes.Equal(result, chunk.chunkHash[:]) {
			errors = append(errors, fmt.Errorf("invalid chunk %d", index))
		}
	}

	return errors
}

func (cp *chunklistPubkey) verify(bytes []byte) error {
	hashedBytes := sha256.Sum256(bytes)
	//var pkcs1SHA256Prefix = []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}

	//var signedMessage = append(pkcs1SHA256Prefix, cp.signature...)
	for _, key := range cp.validKeys {
		err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hashedBytes[:], cp.signature)
		if err == nil {
			return nil
		}
		fmt.Println(err)
	}

	return fmt.Errorf("no valid signature")
}

func (cp chunklistCertificate) verify(bytes []byte) error {
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
