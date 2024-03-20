package rdiff

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type Signature struct {
	blockSize uint32

	checksumType       ChecksumType
	strongChecksumSize uint32

	weakChecksums   map[uint32]int
	strongChecksums [][]byte
}

func WriteSignature(in io.Reader, out io.Writer, checksumType ChecksumType, blockSize uint32, strongChecksumSize uint32) error {
	checksum, err := NewChecksum(checksumType)
	if err != nil {
		return err
	}

	maxStrongChecksumSize := checksum.MaxStrongChecksumSize()
	if strongChecksumSize > maxStrongChecksumSize {
		return fmt.Errorf("strong checksum size %d exceeds max allowed value %d for checksum type %#x", strongChecksumSize, maxStrongChecksumSize, checksumType)
	}

	if err := binary.Write(out, binary.BigEndian, checksumType); err != nil {
		return err
	}

	if err := binary.Write(out, binary.BigEndian, blockSize); err != nil {
		return err
	}

	if err := binary.Write(out, binary.BigEndian, strongChecksumSize); err != nil {
		return err
	}

	blockIndex := 0
	for {
		block := make([]byte, blockSize)
		byteCount, err := io.ReadFull(in, block)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return err
		}

		if byteCount == 0 {
			break
		}

		block = block[:byteCount]

		weakChecksum := checksum.CalculateWeakChecksum(block)
		if err = binary.Write(out, binary.BigEndian, weakChecksum); err != nil {
			return err
		}

		strongChecksum, err := checksum.CalculateStrongChecksum(block, strongChecksumSize)
		if err != nil {
			return err
		}

		if _, err = out.Write(strongChecksum); err != nil {
			return err
		}

		blockIndex++
	}

	return nil
}

func ReadSignature(input io.Reader) (*Signature, error) {
	var checksumType ChecksumType
	if err := binary.Read(input, binary.BigEndian, &checksumType); err != nil {
		return nil, err
	}

	var blockSize uint32
	if err := binary.Read(input, binary.BigEndian, &blockSize); err != nil {
		return nil, err
	}

	var strongChecksumSize uint32
	if err := binary.Read(input, binary.BigEndian, &strongChecksumSize); err != nil {
		return nil, err
	}

	weakChecksums := make(map[uint32]int)
	var strongChecksums [][]byte

	blockIndex := 0
	for {
		var weakChecksum uint32
		err := binary.Read(input, binary.BigEndian, &weakChecksum)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		weakChecksums[weakChecksum] = blockIndex
		blockIndex++

		strongChecksum := make([]byte, strongChecksumSize)
		if _, err = io.ReadFull(input, strongChecksum); err != nil {
			return nil, err
		}
		strongChecksums = append(strongChecksums, strongChecksum)
	}

	return &Signature{
		blockSize,
		checksumType,
		strongChecksumSize,
		weakChecksums,
		strongChecksums,
	}, nil
}
