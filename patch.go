package rdiff

import (
	"encoding/binary"
	"fmt"
	"io"
)

func getParamSize(commandOffset byte) byte {
	switch commandOffset {
	case 0:
		return 1
	case 1:
		return 2
	case 2:
		return 4
	default:
		return 8
	}
}

func readParam(in io.Reader, commandOffset byte) (int64, error) {
	switch getParamSize(commandOffset) {
	case 1:
		var value uint8
		err := binary.Read(in, binary.BigEndian, &value)
		return int64(value), err
	case 2:
		var value uint16
		err := binary.Read(in, binary.BigEndian, &value)
		return int64(value), err
	case 4:
		var value uint32
		err := binary.Read(in, binary.BigEndian, &value)
		return int64(value), err
	default:
		var value uint64
		err := binary.Read(in, binary.BigEndian, &value)
		return int64(value), err
	}
}

func Patch(originalFile io.ReadSeeker, newFile io.Writer, delta io.Reader) error {
	var err error
	var deltaFormat uint32
	if err = binary.Read(delta, binary.BigEndian, &deltaFormat); err != nil {
		return err
	}
	if deltaFormat != DeltaMagicNumber {
		return fmt.Errorf("invalid delta format %x, expected %x", deltaFormat, DeltaMagicNumber)
	}

	for {
		var cmdCode byte
		if err = binary.Read(delta, binary.BigEndian, &cmdCode); err != nil {
			return err
		}

		if CommandType(cmdCode) == End {
			return nil
		} else if cmdCode >= MinReservedCommand {
			return fmt.Errorf("unsupported command code %d", cmdCode)
		}

		var position, length int64
		if cmdCode < MinParameterizedLiteralCommand {
			length = int64(cmdCode)
		} else if cmdCode >= MinParameterizedLiteralCommand && cmdCode < MinCopyCommand {
			if length, err = readParam(delta, cmdCode-MinParameterizedLiteralCommand); err != nil {
				return err
			}
		} else {
			offset := cmdCode - MinCopyCommand
			positionOffset := offset / 4
			lengthOffset := offset - positionOffset*4
			if position, err = readParam(delta, positionOffset); err != nil {
				return err
			}
			if length, err = readParam(delta, lengthOffset); err != nil {
				return err
			}
		}

		if cmdCode < MinCopyCommand {
			if _, err = io.CopyN(newFile, delta, length); err != nil {
				return err
			}
		} else {
			if _, err = originalFile.Seek(position, io.SeekStart); err != nil {
				return err
			}

			if _, err = io.CopyN(newFile, originalFile, length); err != nil {
				return err
			}
		}
	}
}
