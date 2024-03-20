package rdiff

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/balena-os/circbuf"
	"io"
)

func getByteSize(value uint64) byte {
	if (value >> 32) > 0 {
		return 8
	} else if (value >> 16) > 0 {
		return 4
	} else if (value >> 8) > 0 {
		return 2
	} else {
		return 1
	}
}

func getCommandOffset(size byte) byte {
	switch size {
	case 1:
		return 0
	case 2:
		return 1
	case 4:
		return 2
	default:
		return 3
	}
}

func writeParam(out io.Writer, value uint64, size uint8) error {
	switch size {
	case 1:
		return binary.Write(out, binary.BigEndian, uint8(value))
	case 2:
		return binary.Write(out, binary.BigEndian, uint16(value))
	case 4:
		return binary.Write(out, binary.BigEndian, uint32(value))
	case 8:
		return binary.Write(out, binary.BigEndian, value)
	}

	return fmt.Errorf("invalid data size: %v", size)
}

type Command struct {
	commandType    CommandType
	position       uint64
	length         uint64
	literalData    []byte
	maxLiteralSize uint32
}

func writeCommand(out io.Writer, command *Command) error {
	if command.commandType == Literal {
		if command.length == 0 {
			return fmt.Errorf("empty literal")
		} else if command.length < uint64(MinParameterizedLiteralCommand) {
			if _, err := out.Write([]byte{byte(command.length)}); err != nil {
				return err
			}
		} else {
			byteSize := getByteSize(command.length)
			offset := getCommandOffset(byteSize)
			commandCode := MinParameterizedLiteralCommand + offset
			if _, err := out.Write([]byte{commandCode}); err != nil {
				return err
			}

			if err := writeParam(out, command.length, byteSize); err != nil {
				return err
			}
		}
		if _, err := out.Write(command.literalData); err != nil {
			return err
		}
		command.literalData = make([]byte, 0, command.maxLiteralSize)
	} else if command.commandType == Copy {
		positionByteSize := getByteSize(command.position)
		lengthByteSize := getByteSize(command.length)
		positionOffset := getCommandOffset(positionByteSize)
		lengthOffset := getCommandOffset(lengthByteSize)

		commandCode := MinCopyCommand + positionOffset*4 + lengthOffset
		if _, err := out.Write([]byte{commandCode}); err != nil {
			return err
		}

		if err := writeParam(out, command.position, positionByteSize); err != nil {
			return err
		}

		if err := writeParam(out, command.length, lengthByteSize); err != nil {
			return err
		}
	} else if command.commandType == End {
		if _, err := out.Write([]byte{0}); err != nil {
			return err
		}
	}

	return nil
}

func WriteDelta(signature *Signature, in io.Reader, out io.Writer, maxLiteralSize uint32) error {
	if err := binary.Write(out, binary.BigEndian, DeltaMagicNumber); err != nil {
		return err
	}

	blockSize := uint64(signature.blockSize)
	block, err := circbuf.NewBuffer(int64(blockSize))
	if err != nil {
		return err
	}

	firstByte := byte(0)
	position := ^uint64(0)
	checksum, err := NewChecksum(signature.checksumType)
	input := bufio.NewReaderSize(in, int(blockSize))
	literalCommand := &Command{commandType: Literal, literalData: make([]byte, 0, maxLiteralSize), maxLiteralSize: maxLiteralSize}
	for {
		position++
		nextByte, err := input.ReadByte()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return err
		}

		if block.TotalWritten() > 0 {
			if firstByte, err = block.Get(0); err != nil {
				return err
			}
		}

		checksum.Rollin(nextByte)
		if err = block.WriteByte(nextByte); err != nil {
			return err
		}

		if checksum.Count() < blockSize {
			continue
		} else if checksum.Count() > blockSize {
			firstBytePosition := position - blockSize
			if (len(literalCommand.literalData) >= int(maxLiteralSize)) || (literalCommand.length > 0 && literalCommand.position+literalCommand.length != firstBytePosition) {
				if err := writeCommand(out, literalCommand); err != nil {
					return err
				}
			}

			literalCommand.literalData = append(literalCommand.literalData, firstByte)
			if literalCommand.length == 0 {
				literalCommand.position = firstBytePosition
			}
			literalCommand.length++

			checksum.Rollout(firstByte)
		}

		if blockIndex, ok := signature.weakChecksums[checksum.Digest()]; ok {
			strongChecksum, err := checksum.CalculateStrongChecksum(block.Bytes(), signature.strongChecksumSize)
			if err != nil {
				return err
			}

			if bytes.Equal(strongChecksum, signature.strongChecksums[blockIndex]) {
				if len(literalCommand.literalData) > 0 {
					if err = writeCommand(out, literalCommand); err != nil {
						return err
					}
				}

				if err = writeCommand(out, &Command{commandType: Copy, position: uint64(blockIndex) * blockSize, length: blockSize}); err != nil {
					return err
				}

				block.Reset()
				checksum.Reset()
			}
		}
	}

	remainingBytes := append(literalCommand.literalData, block.Bytes()...)
	remainingBytesLen := len(remainingBytes)
	for begin := 0; begin < remainingBytesLen; begin += int(maxLiteralSize) {
		end := begin + int(maxLiteralSize)
		if end > remainingBytesLen {
			end = remainingBytesLen
		}
		literalCommand.literalData = remainingBytes[begin:end]
		literalCommand.length = uint64(len(literalCommand.literalData))
		if literalCommand.length > 0 {
			if err = writeCommand(out, literalCommand); err != nil {
				return err
			}
		}
	}

	return writeCommand(out, &Command{commandType: End})
}
