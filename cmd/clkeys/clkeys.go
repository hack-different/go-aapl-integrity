package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"debug/macho"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
)

const ChunklistKeyCountSymbol = "_rev1_chunklist_num_pubkeys"
const ChunklistKeysSymbol = "_rev1_chunklist_pubkeys"
const ChunklistKeyCountSize = 8
const ChunklistKeySize = 2048/8
const ChunklistKeyDataType = "RSA PUBLIC KEY"

type Kernel struct {
	kernelObject *macho.File
}

func loadKernel(path string) (*Kernel, error) {
	result := new(Kernel)
	kernelObject, err := macho.Open(path)
	if err != nil {
		return nil, err
	}
	result.kernelObject = kernelObject

	return result, nil
}

func parseKey(keyBytes []byte) *rsa.PublicKey {
	result := new(rsa.PublicKey)
	result.E = 0x010001
	result.N = big.NewInt(0)
	result.N.SetBytes(keyBytes)
	fmt.Println(result.N.String())
	return result
}

func getKeys(kernel *Kernel) ([]*rsa.PublicKey, error) {
	var keyCount uint64
	countSymbol := getSymbol(kernel, ChunklistKeyCountSymbol)
	keySymbol := getSymbol(kernel, ChunklistKeysSymbol)

	countBytes, err := getConstantBytes(kernel, countSymbol, ChunklistKeyCountSize)
	if err != nil {
		return nil, err
	}
	err = binary.Read(bytes.NewReader(countBytes), binary.LittleEndian, &keyCount)
	if err != nil {
		return nil, err
	}

	keys, err := getConstantBytes(kernel, keySymbol, keyCount * (ChunklistKeySize + 4))
	if err != nil {
		return nil, err
	}
	result := make([]*rsa.PublicKey, keyCount)
	for index, _ := range result {
		start := (index * (ChunklistKeySize + 4)) + 4
		end := start + ChunklistKeySize
		keyBytes := keys[start:end]
		result[index] = parseKey(keyBytes)
	}

	return result, nil
}

func getSymbol(kernel *Kernel, name string) macho.Symbol {
	for _, symbol := range kernel.kernelObject.Symtab.Syms {
		if symbol.Name == name {
			return symbol
		}
	}

	return macho.Symbol{}
}

func getConstantBytes(kernel *Kernel, symbol macho.Symbol, length uint64) ([]byte, error) {
	constData := kernel.kernelObject.Sections[symbol.Sect - 1]
	offset := symbol.Value - constData.Addr
	result := make([]byte, length)

	count, err := constData.ReadAt(result, int64(offset))
	if uint64(count) != length {
		err = fmt.Errorf("could not read %x bytes", length)
	}
	if err != nil {
		return nil, err
	}

	return result, nil
}

func formatKey(key *rsa.PublicKey) []byte {
	keyBytes := x509.MarshalPKCS1PublicKey(key)
	block := new(pem.Block)
	block.Type = ChunklistKeyDataType
	block.Bytes = keyBytes
	return pem.EncodeToMemory(block)
}

func main() {
	stdErr := log.New(os.Stderr, "error: ", 0)
	if len(os.Args) < 2 {
		stdErr.Println("no kernel file provided")
		os.Exit(-1)
	}

	_, err := os.Stat(os.Args[1])
	if os.IsExist(err) {
		stdErr.Println("kernel file not found")
		os.Exit(-2)
	}

	kernel, err := loadKernel(os.Args[1])
	if err != nil {
		stdErr.Println(err)
		os.Exit(-4)
	}

	keys, err := getKeys(kernel)
	if err != nil {
		stdErr.Println(err)
		os.Exit(-5)
	}

	for _, key := range keys {
		output := formatKey(key)
		os.Stdout.Write(output)
	}
}