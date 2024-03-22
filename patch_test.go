package rdiff

import (
	"bytes"
	cryptoRand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPatch_NoChange(t *testing.T) {
	for _, checksumType := range ChecksumTypes {
		for _, strongChecksumSize := range StrongChecksumSizes {
			checksum, err := NewChecksum(checksumType)
			if maxStrongChecksumSize := checksum.MaxStrongChecksumSize(); strongChecksumSize > maxStrongChecksumSize {
				continue
			}

			// Generate file
			_, blockSize, _, originalFile, err := generateFile(1, 100)
			assert.Nil(t, err)

			// Calculate delta
			delta, err := generateDelta(originalFile, originalFile, uint32(blockSize), checksumType, strongChecksumSize, uint32(blockSize*2))
			assert.Nil(t, err)

			// Apply patch
			actualNewFile := &bytes.Buffer{}
			err = Patch(bytes.NewReader(originalFile), actualNewFile, delta)
			assert.Nil(t, err)

			assert.Equal(t, originalFile, actualNewFile.Bytes())
		}
	}
}

func TestPatch_PrependFile(t *testing.T) {
	for _, checksumType := range ChecksumTypes {
		for _, strongChecksumSize := range StrongChecksumSizes {
			checksum, err := NewChecksum(checksumType)
			if maxStrongChecksumSize := checksum.MaxStrongChecksumSize(); strongChecksumSize > maxStrongChecksumSize {
				continue
			}

			// Generate file
			_, blockSize, _, originalFile, err := generateFile(2, 100)
			assert.Nil(t, err)

			// Insert random bytes at the beginning of the file
			insertDataLength := rand64(1, 10)
			insertData := make([]byte, insertDataLength)
			newFile := make([]byte, 0)
			newFile = append(newFile, insertData...)
			newFile = append(newFile, originalFile...)

			// Calculate delta
			delta, err := generateDelta(originalFile, newFile, uint32(blockSize), checksumType, strongChecksumSize, uint32(blockSize*2))
			assert.Nil(t, err)

			// Apply patch
			actualNewFile := &bytes.Buffer{}
			err = Patch(bytes.NewReader(originalFile), actualNewFile, delta)
			assert.Nil(t, err)

			assert.Equal(t, newFile, actualNewFile.Bytes())
		}
	}
}

func TestPatch_AppendFile(t *testing.T) {
	for _, checksumType := range ChecksumTypes {
		for _, strongChecksumSize := range StrongChecksumSizes {
			checksum, err := NewChecksum(checksumType)
			if maxStrongChecksumSize := checksum.MaxStrongChecksumSize(); strongChecksumSize > maxStrongChecksumSize {
				continue
			}

			// Generate file
			_, blockSize, _, originalFile, err := generateFile(2, 100)
			assert.Nil(t, err)

			// Append random bytes at the end of the file
			insertDataLength := rand64(1, 50)
			insertData := make([]byte, insertDataLength)
			newFile := make([]byte, 0)
			newFile = append(newFile, originalFile...)
			newFile = append(newFile, insertData...)

			// Calculate delta
			delta, err := generateDelta(originalFile, newFile, uint32(blockSize), checksumType, strongChecksumSize, uint32(blockSize*2))
			assert.Nil(t, err)

			// Apply patch
			actualNewFile := &bytes.Buffer{}
			err = Patch(bytes.NewReader(originalFile), actualNewFile, delta)
			assert.Nil(t, err)

			assert.Equal(t, newFile, actualNewFile.Bytes())
		}
	}
}

func TestPatch_InsertBetweenBlocks(t *testing.T) {
	for _, checksumType := range ChecksumTypes {
		for _, strongChecksumSize := range StrongChecksumSizes {
			checksum, err := NewChecksum(checksumType)
			if maxStrongChecksumSize := checksum.MaxStrongChecksumSize(); strongChecksumSize > maxStrongChecksumSize {
				continue
			}

			// Generate file
			blockNumber, blockSize, _, originalFile, err := generateFile(2, 100)
			assert.Nil(t, err)

			// Insert random bytes at the beginning of a block
			insertDataLength := rand64(1, 90)
			insertData, err := generateBytes(insertDataLength)
			assert.Nil(t, err)
			insertPosition := rand64(1, int(blockNumber)-2) * blockSize
			newFile := make([]byte, insertPosition)
			copy(newFile, originalFile[:insertPosition])
			newFile = append(append(newFile, insertData...), originalFile[insertPosition:]...)

			// Calculate delta
			delta, err := generateDelta(originalFile, newFile, uint32(blockSize), checksumType, strongChecksumSize, uint32(blockSize*2))
			assert.Nil(t, err)

			// Apply patch
			actualNewFile := &bytes.Buffer{}
			err = Patch(bytes.NewReader(originalFile), actualNewFile, delta)
			assert.Nil(t, err)

			assert.Equal(t, newFile, actualNewFile.Bytes())
		}
	}
}

func TestPatch_ModifyBlock(t *testing.T) {
	for _, checksumType := range ChecksumTypes {
		for _, strongChecksumSize := range StrongChecksumSizes {
			checksum, err := NewChecksum(checksumType)
			if maxStrongChecksumSize := checksum.MaxStrongChecksumSize(); strongChecksumSize > maxStrongChecksumSize {
				continue
			}

			// Generate file
			blockNumber, blockSize, _, originalFile, err := generateFile(2, 100)
			assert.Nil(t, err)

			// Modify one of the blocks
			newFile := make([]byte, 0)
			newFile = append(newFile, originalFile...)
			blockIndex := rand64(0, int(blockNumber)-2)
			blockBegin := blockIndex * blockSize
			blockEnd := blockBegin + blockSize
			_, err = cryptoRand.Read(newFile[blockBegin:blockEnd])
			assert.Nil(t, err)

			// Calculate delta
			delta, err := generateDelta(originalFile, newFile, uint32(blockSize), checksumType, strongChecksumSize, uint32(blockSize*2))
			assert.Nil(t, err)

			// Apply patch
			actualNewFile := &bytes.Buffer{}
			err = Patch(bytes.NewReader(originalFile), actualNewFile, delta)
			assert.Nil(t, err)

			assert.Equal(t, newFile, actualNewFile.Bytes())
		}
	}
}

func TestPatch_RemoveBlock(t *testing.T) {
	for _, checksumType := range ChecksumTypes {
		for _, strongChecksumSize := range StrongChecksumSizes {
			checksum, err := NewChecksum(checksumType)
			if maxStrongChecksumSize := checksum.MaxStrongChecksumSize(); strongChecksumSize > maxStrongChecksumSize {
				continue
			}

			// Generate file
			blockNumber, blockSize, _, originalFile, err := generateFile(2, 100)
			assert.Nil(t, err)

			// Remove one of the blocks
			blockIndex := rand64(0, int(blockNumber)-2)
			blockBegin := blockIndex * blockSize
			blockEnd := blockBegin + blockSize
			newFile := make([]byte, 0)
			newFile = append(newFile, originalFile[:blockBegin]...)
			newFile = append(newFile, originalFile[blockEnd:]...)

			// Calculate delta
			delta, err := generateDelta(originalFile, newFile, uint32(blockSize), checksumType, strongChecksumSize, uint32(blockSize*2))
			assert.Nil(t, err)

			// Apply patch
			actualNewFile := &bytes.Buffer{}
			err = Patch(bytes.NewReader(originalFile), actualNewFile, delta)
			assert.Nil(t, err)

			assert.Equal(t, newFile, actualNewFile.Bytes())
		}
	}
}

func TestPatch_SmallMaxLiteralSize(t *testing.T) {
	for _, checksumType := range ChecksumTypes {
		for _, strongChecksumSize := range StrongChecksumSizes {
			checksum, err := NewChecksum(checksumType)
			if maxStrongChecksumSize := checksum.MaxStrongChecksumSize(); strongChecksumSize > maxStrongChecksumSize {
				continue
			}

			// Generate file
			_, blockSize, lastBlockSize, originalFile, err := generateFile(2, 100)
			assert.Nil(t, err)

			maxLiteralSize := lastBlockSize/2 + 1

			// Calculate delta
			delta, err := generateDelta(originalFile, originalFile, uint32(blockSize), checksumType, strongChecksumSize, uint32(maxLiteralSize))
			assert.Nil(t, err)

			// Apply patch
			actualNewFile := &bytes.Buffer{}
			err = Patch(bytes.NewReader(originalFile), actualNewFile, delta)
			assert.Nil(t, err)

			assert.Equal(t, originalFile, actualNewFile.Bytes())
		}
	}
}
