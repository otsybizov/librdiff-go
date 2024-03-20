package rdiff

import (
	"bytes"
	"encoding/binary"
	"testing"

	cryptoRand "crypto/rand"
	"github.com/stretchr/testify/assert"
)

func TestWriteDelta_NoChange(t *testing.T) {
	for _, checksumType := range ChecksumTypes {
		for _, strongChecksumSize := range StrongChecksumSizes {
			checksum, err := NewChecksum(checksumType)
			if maxStrongChecksumSize := checksum.MaxStrongChecksumSize(); strongChecksumSize > maxStrongChecksumSize {
				continue
			}

			// Generate file
			blockNumber, blockSize, lastBlockSize, originalFile, err := generateFile(1, 100)
			assert.Nil(t, err)

			// Generate expected delta
			expectedDelta := &bytes.Buffer{}
			err = binary.Write(expectedDelta, binary.BigEndian, DeltaMagicNumber)
			assert.Nil(t, err)
			// Copy all blocks except the last one, the last block is written as literal command because it is less than the others
			for i := uint64(0); i < blockNumber; i++ {
				if i == blockNumber-1 {
					err = writeCommand(expectedDelta, &Command{commandType: Literal, length: lastBlockSize, literalData: originalFile[i*blockSize:]})
				} else {
					err = writeCommand(expectedDelta, &Command{commandType: Copy, position: i * blockSize, length: blockSize})
				}
				assert.Nil(t, err)
			}
			// End command
			expectedDelta.WriteByte(0)

			// Calculate actual delta
			actualDelta, err := generateDelta(originalFile, originalFile, uint32(blockSize), checksumType, strongChecksumSize, uint32(blockSize*2))
			assert.Nil(t, err)

			assert.Equal(t, expectedDelta, actualDelta)
		}
	}
}

func TestWriteDelta_PrependFile(t *testing.T) {
	for _, checksumType := range ChecksumTypes {
		for _, strongChecksumSize := range StrongChecksumSizes {
			checksum, err := NewChecksum(checksumType)
			if maxStrongChecksumSize := checksum.MaxStrongChecksumSize(); strongChecksumSize > maxStrongChecksumSize {
				continue
			}

			// Generate original file
			blockNumber, blockSize, lastBlockSize, originalFile, err := generateFile(2, 100)
			assert.Nil(t, err)

			// Insert random bytes at the beginning of the file
			insertDataLength := rand64(1, 70)
			insertData := make([]byte, insertDataLength)
			newFile := make([]byte, 0)
			newFile = append(newFile, insertData...)
			newFile = append(newFile, originalFile...)

			// Generate expected delta
			expectedDelta := &bytes.Buffer{}
			err = binary.Write(expectedDelta, binary.BigEndian, DeltaMagicNumber)
			assert.Nil(t, err)
			err = writeCommand(expectedDelta, &Command{commandType: Literal, length: insertDataLength, literalData: insertData})
			assert.Nil(t, err)
			for i := uint64(0); i < blockNumber; i++ {
				// The last block is written as literal command because it is less than the others
				if i == blockNumber-1 {
					lastBlock := originalFile[i*blockSize:]
					err = writeCommand(expectedDelta, &Command{commandType: Literal, length: lastBlockSize, literalData: lastBlock})
				} else {
					err = writeCommand(expectedDelta, &Command{commandType: Copy, position: i * blockSize, length: blockSize})
				}
				assert.Nil(t, err)
			}
			// End command
			expectedDelta.WriteByte(0)

			// Calculate actual delta
			actualDelta, err := generateDelta(originalFile, newFile, uint32(blockSize), checksumType, strongChecksumSize, uint32(blockSize*2))
			assert.Nil(t, err)

			assert.Equal(t, expectedDelta, actualDelta)
		}
	}
}

func TestWriteDelta_AppendFile(t *testing.T) {
	for _, checksumType := range ChecksumTypes {
		for _, strongChecksumSize := range StrongChecksumSizes {
			checksum, err := NewChecksum(checksumType)
			if maxStrongChecksumSize := checksum.MaxStrongChecksumSize(); strongChecksumSize > maxStrongChecksumSize {
				continue
			}

			// Generate original file
			blockNumber, blockSize, lastBlockSize, originalFile, err := generateFile(2, 100)
			assert.Nil(t, err)

			// Append random bytes at the end of the file
			insertDataLength := rand64(1, 80)
			insertData := make([]byte, insertDataLength)
			newFile := make([]byte, 0)
			newFile = append(newFile, originalFile...)
			newFile = append(newFile, insertData...)

			// Generate expected delta
			expectedDelta := &bytes.Buffer{}
			err = binary.Write(expectedDelta, binary.BigEndian, DeltaMagicNumber)
			assert.Nil(t, err)
			for i := uint64(0); i < blockNumber-1; i++ {
				err = writeCommand(expectedDelta, &Command{commandType: Copy, position: i * blockSize, length: blockSize})
				assert.Nil(t, err)
			}
			// Write literal command that includes the last block of original file + inserted data
			lastBlock := originalFile[(blockNumber-1)*blockSize:]
			err = writeCommand(expectedDelta, &Command{commandType: Literal, length: lastBlockSize + insertDataLength, literalData: append(lastBlock, insertData...)})
			assert.Nil(t, err)
			// End command
			expectedDelta.WriteByte(0)

			// Calculate actual delta
			actualDelta, err := generateDelta(originalFile, newFile, uint32(blockSize), checksumType, strongChecksumSize, uint32(blockSize*2))
			assert.Nil(t, err)

			assert.Equal(t, expectedDelta, actualDelta)
		}
	}
}

func TestWriteDelta_InsertBetweenBlocks(t *testing.T) {
	for _, checksumType := range ChecksumTypes {
		for _, strongChecksumSize := range StrongChecksumSizes {
			checksum, err := NewChecksum(checksumType)
			if maxStrongChecksumSize := checksum.MaxStrongChecksumSize(); strongChecksumSize > maxStrongChecksumSize {
				continue
			}

			// Generate original file
			blockNumber, blockSize, lastBlockSize, originalFile, err := generateFile(3, 100)
			assert.Nil(t, err)

			// Insert random bytes at the beginning of a block
			insertDataLength := rand64(1, 50)
			insertData, err := generateBytes(insertDataLength)
			assert.Nil(t, err)
			insertPosition := rand64(1, int(blockNumber)-2) * blockSize
			newFile := make([]byte, insertPosition)
			copy(newFile, originalFile[:insertPosition])
			newFile = append(append(newFile, insertData...), originalFile[insertPosition:]...)

			// Generate expected delta
			expectedDelta := &bytes.Buffer{}
			err = binary.Write(expectedDelta, binary.BigEndian, DeltaMagicNumber)
			assert.Nil(t, err)

			for i := uint64(0); i < blockNumber; i++ {
				position := i * blockSize
				// The inserted data are written as a literal command
				if position == insertPosition {
					err = writeCommand(expectedDelta, &Command{commandType: Literal, length: insertDataLength, literalData: insertData})
					assert.Nil(t, err)
				}

				if i == blockNumber-1 {
					lastBlock := originalFile[i*blockSize:]
					err = writeCommand(expectedDelta, &Command{commandType: Literal, length: lastBlockSize, literalData: lastBlock})
				} else {
					err = writeCommand(expectedDelta, &Command{commandType: Copy, position: i * blockSize, length: blockSize})
				}
				assert.Nil(t, err)
			}

			// End command
			expectedDelta.WriteByte(0)

			// Calculate actual delta
			actualDelta, err := generateDelta(originalFile, newFile, uint32(blockSize), checksumType, strongChecksumSize, uint32(blockSize*2))
			assert.Nil(t, err)

			assert.Equal(t, expectedDelta, actualDelta)
		}
	}
}

func TestWriteDelta_ModifyBlock(t *testing.T) {
	for _, checksumType := range ChecksumTypes {
		for _, strongChecksumSize := range StrongChecksumSizes {
			checksum, err := NewChecksum(checksumType)
			if maxStrongChecksumSize := checksum.MaxStrongChecksumSize(); strongChecksumSize > maxStrongChecksumSize {
				continue
			}

			// Generate original file
			blockNumber, blockSize, lastBlockSize, originalFile, err := generateFile(3, 100)
			assert.Nil(t, err)

			// Modify one of the blocks
			newFile := make([]byte, 0)
			newFile = append(newFile, originalFile...)
			blockIndex := rand64(0, int(blockNumber)-2)
			blockBegin := blockIndex * blockSize
			blockEnd := blockBegin + blockSize
			_, err = cryptoRand.Read(newFile[blockBegin:blockEnd])
			assert.Nil(t, err)

			// Generate expected delta
			expectedDelta := &bytes.Buffer{}
			err = binary.Write(expectedDelta, binary.BigEndian, DeltaMagicNumber)
			assert.Nil(t, err)
			for i := uint64(0); i < blockNumber; i++ {
				if i == blockIndex {
					err = writeCommand(expectedDelta, &Command{commandType: Literal, length: blockSize, literalData: newFile[blockBegin:blockEnd]})
				} else if i == blockNumber-1 {
					err = writeCommand(expectedDelta, &Command{commandType: Literal, length: lastBlockSize, literalData: originalFile[i*blockSize:]})
				} else {
					err = writeCommand(expectedDelta, &Command{commandType: Copy, position: i * blockSize, length: blockSize})
				}
				assert.Nil(t, err)
			}
			// End command
			expectedDelta.WriteByte(0)

			// Calculate actual delta
			actualDelta, err := generateDelta(originalFile, newFile, uint32(blockSize), checksumType, strongChecksumSize, uint32(blockSize*2))
			assert.Nil(t, err)

			assert.Equal(t, expectedDelta, actualDelta)
		}
	}
}

func TestWriteDelta_RemoveBlock(t *testing.T) {
	for _, checksumType := range ChecksumTypes {
		for _, strongChecksumSize := range StrongChecksumSizes {
			checksum, err := NewChecksum(checksumType)
			if maxStrongChecksumSize := checksum.MaxStrongChecksumSize(); strongChecksumSize > maxStrongChecksumSize {
				continue
			}

			// Generate original file
			blockNumber, blockSize, lastBlockSize, originalFile, err := generateFile(3, 100)
			assert.Nil(t, err)

			// Remove one of the blocks
			blockIndex := rand64(0, int(blockNumber)-2)
			blockBegin := blockIndex * blockSize
			blockEnd := blockBegin + blockSize
			newFile := make([]byte, 0)
			newFile = append(newFile, originalFile[:blockBegin]...)
			newFile = append(newFile, originalFile[blockEnd:]...)

			// Generate expected delta
			expectedDelta := &bytes.Buffer{}
			err = binary.Write(expectedDelta, binary.BigEndian, DeltaMagicNumber)
			assert.Nil(t, err)
			for i := uint64(0); i < blockNumber; i++ {
				if i == blockNumber-1 {
					err = writeCommand(expectedDelta, &Command{commandType: Literal, length: lastBlockSize, literalData: originalFile[i*blockSize:]})
				} else if i != blockIndex {
					err = writeCommand(expectedDelta, &Command{commandType: Copy, position: i * blockSize, length: blockSize})
				}
				assert.Nil(t, err)
			}
			// End command
			expectedDelta.WriteByte(0)

			// Calculate actual delta
			actualDelta, err := generateDelta(originalFile, newFile, uint32(blockSize), checksumType, strongChecksumSize, uint32(blockSize*2))
			assert.Nil(t, err)

			assert.Equal(t, expectedDelta, actualDelta)
		}
	}
}

func TestWriteDelta_SmallMaxLiteralSize(t *testing.T) {
	for _, checksumType := range ChecksumTypes {
		for _, strongChecksumSize := range StrongChecksumSizes {
			checksum, err := NewChecksum(checksumType)
			if maxStrongChecksumSize := checksum.MaxStrongChecksumSize(); strongChecksumSize > maxStrongChecksumSize {
				continue
			}

			// Generate file
			blockNumber, blockSize, lastBlockSize, originalFile, err := generateFile(1, 100)
			assert.Nil(t, err)

			maxLiteralSize := lastBlockSize/2 + 1

			// Generate expected delta
			expectedDelta := &bytes.Buffer{}
			err = binary.Write(expectedDelta, binary.BigEndian, DeltaMagicNumber)
			assert.Nil(t, err)
			for i := uint64(0); i < blockNumber; i++ {
				// The last block is split into 2 literal commands
				if i == blockNumber-1 {
					err = writeCommand(expectedDelta, &Command{commandType: Literal, length: maxLiteralSize, literalData: originalFile[i*blockSize : i*blockSize+maxLiteralSize]})
					assert.Nil(t, err)
					err = writeCommand(expectedDelta, &Command{commandType: Literal, length: lastBlockSize - maxLiteralSize, literalData: originalFile[i*blockSize+maxLiteralSize:]})
				} else {
					err = writeCommand(expectedDelta, &Command{commandType: Copy, position: i * blockSize, length: blockSize})
				}
				assert.Nil(t, err)
			}
			// End command
			expectedDelta.WriteByte(0)

			// Calculate actual delta
			actualDelta, err := generateDelta(originalFile, originalFile, uint32(blockSize), checksumType, strongChecksumSize, uint32(maxLiteralSize))
			assert.Nil(t, err)

			assert.Equal(t, expectedDelta, actualDelta)
		}
	}
}
