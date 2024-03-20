package rdiff

import (
	"bytes"

	cryptoRand "crypto/rand"
	mathRand "math/rand"
)

var (
	BlockSizes          = []uint32{100, 200, 500}
	ChecksumTypes       = []ChecksumType{Rollsum_Md4, Rollsum_Blake2b, Rabinkarp_Md4, Rabinkarp_Blake2b}
	StrongChecksumSizes = []uint32{8, 16, 32}
)

func rand(begin, end int) int {
	if begin == end {
		return begin
	}

	return mathRand.Intn(end-begin) + begin
}

func rand32(begin, end int) uint32 {
	if begin == end {
		return uint32(begin)
	}

	return uint32(mathRand.Intn(end-begin) + begin)
}

func rand64(begin, end int) uint64 {
	if begin == end {
		return uint64(begin)
	}

	return uint64(mathRand.Intn(end-begin) + begin)
}

func generateBytes(size uint64) (block []byte, err error) {
	block = make([]byte, size)
	_, err = cryptoRand.Read(block)

	return block, err
}

func generateFile(minBlockNumber, minBlockSize int) (blockNumber uint64, blockSize uint64, lastBlockSize uint64, content []byte, err error) {
	blockNumber = rand64(minBlockNumber, 256)
	blockSize = rand64(minBlockSize, 65536)
	lastBlockSize = rand64(int(blockSize/2), int(blockSize-1))
	content, err = generateBytes((blockNumber-1)*blockSize + lastBlockSize)

	return blockNumber, blockSize, lastBlockSize, content, err
}

func generateDelta(originalContent []byte, newContent []byte, blockSize uint32, checksumType ChecksumType, strongChecksumSize uint32, maxLiteralSize uint32) (delta *bytes.Buffer, err error) {
	signatureBuffer := &bytes.Buffer{}
	if err := WriteSignature(bytes.NewReader(originalContent), signatureBuffer, checksumType, blockSize, strongChecksumSize); err != nil {
		return nil, err
	}

	signature, err := ReadSignature(signatureBuffer)
	if err != nil {
		return nil, err
	}

	delta = &bytes.Buffer{}
	err = WriteDelta(signature, bytes.NewReader(newContent), delta, maxLiteralSize)

	return delta, nil
}
