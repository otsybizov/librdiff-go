package rdiff

import (
	"bytes"
	"encoding/binary"
	"testing"

	cryptoRand "crypto/rand"
	"github.com/stretchr/testify/assert"
)

type TestSignatureData struct {
	blockSize   uint32
	fileContent []byte

	checksumType       ChecksumType
	strongChecksumSize uint32

	weakChecksums   []uint32
	strongChecksums [][]byte
}

func generateTestData() (data []TestSignatureData, err error) {
	for _, blockSize := range BlockSizes {
		for _, checksumType := range ChecksumTypes {
			for _, strongChecksumSize := range StrongChecksumSizes {
				checksum, err := NewChecksum(checksumType)
				if err != nil {
					return nil, err
				}

				if maxStrongChecksumSize := checksum.MaxStrongChecksumSize(); strongChecksumSize > maxStrongChecksumSize {
					continue
				}

				signatureData := TestSignatureData{
					blockSize:          blockSize,
					checksumType:       checksumType,
					strongChecksumSize: strongChecksumSize,
				}

				blockNumber := rand(1, 256)
				for i := 0; i < blockNumber; i++ {
					size := blockSize
					if i == blockNumber-1 {
						size = rand32(1, int(blockSize))
					}

					block := make([]byte, size)
					if _, err := cryptoRand.Read(block); err != nil {
						return nil, err
					}
					signatureData.fileContent = append(signatureData.fileContent, block...)

					weakChecksum := checksum.CalculateWeakChecksum(block)
					signatureData.weakChecksums = append(signatureData.weakChecksums, weakChecksum)
					strongChecksum, _ := checksum.CalculateStrongChecksum(block, signatureData.strongChecksumSize)
					signatureData.strongChecksums = append(signatureData.strongChecksums, strongChecksum)
				}

				data = append(data, signatureData)
			}
		}
	}

	return data, nil
}

func TestWriteSignature(t *testing.T) {
	testData, err := generateTestData()
	assert.Nil(t, err)

	for _, signatureData := range testData {
		expectedBuffer := &bytes.Buffer{}
		err = binary.Write(expectedBuffer, binary.BigEndian, signatureData.checksumType)
		assert.Nil(t, err)
		err = binary.Write(expectedBuffer, binary.BigEndian, signatureData.blockSize)
		assert.Nil(t, err)
		err = binary.Write(expectedBuffer, binary.BigEndian, signatureData.strongChecksumSize)
		assert.Nil(t, err)
		for i := 0; i < len(signatureData.weakChecksums); i++ {
			err = binary.Write(expectedBuffer, binary.BigEndian, signatureData.weakChecksums[i])
			assert.Nil(t, err)
			n, err := expectedBuffer.Write(signatureData.strongChecksums[i])
			assert.Nil(t, err)
			assert.Equal(t, len(signatureData.strongChecksums[i]), n)
		}

		inputBuffer := bytes.NewReader(signatureData.fileContent)
		outputBuffer := &bytes.Buffer{}
		outputBuffer.Grow(expectedBuffer.Len())
		err = WriteSignature(inputBuffer, outputBuffer, signatureData.checksumType, signatureData.blockSize, signatureData.strongChecksumSize)
		assert.Nil(t, err)

		assert.Equal(t, expectedBuffer, outputBuffer)
	}
}

func TestReadSignature(t *testing.T) {
	testData, err := generateTestData()
	assert.Nil(t, err)

	for _, signatureData := range testData {
		inputBuffer := &bytes.Buffer{}
		expectedSignature := &Signature{}
		expectedSignature.checksumType = signatureData.checksumType
		err = binary.Write(inputBuffer, binary.BigEndian, signatureData.checksumType)
		assert.Nil(t, err)
		expectedSignature.blockSize = signatureData.blockSize
		err = binary.Write(inputBuffer, binary.BigEndian, signatureData.blockSize)
		assert.Nil(t, err)
		expectedSignature.strongChecksumSize = signatureData.strongChecksumSize
		err = binary.Write(inputBuffer, binary.BigEndian, signatureData.strongChecksumSize)
		assert.Nil(t, err)
		expectedSignature.weakChecksums = make(map[uint32]int)
		expectedSignature.strongChecksums = append(expectedSignature.strongChecksums, signatureData.strongChecksums...)
		for i := 0; i < len(signatureData.weakChecksums); i++ {
			weakChecksum := signatureData.weakChecksums[i]
			expectedSignature.weakChecksums[weakChecksum] = i
			err = binary.Write(inputBuffer, binary.BigEndian, weakChecksum)
			assert.Nil(t, err)
			n, err := inputBuffer.Write(signatureData.strongChecksums[i])
			assert.Nil(t, err)
			assert.Equal(t, len(signatureData.strongChecksums[i]), n)
		}

		actualSignature, err := ReadSignature(inputBuffer)
		assert.Nil(t, err)

		assert.Equal(t, expectedSignature, actualSignature)
	}
}
