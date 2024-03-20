package rdiff

import (
	"fmt"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/md4"
)

type Checksum struct {
	checksumType ChecksumType
	rollsum      *RollingChecksum
	rabinkarp    *RabinkarpChecksum
}

func NewChecksum(checksumType ChecksumType) (*Checksum, error) {
	switch checksumType {
	case Rollsum_Md4, Rollsum_Blake2b:
		return &Checksum{checksumType: checksumType, rollsum: NewRollingChecksum()}, nil
	case Rabinkarp_Md4, Rabinkarp_Blake2b:
		return &Checksum{checksumType: checksumType, rabinkarp: NewRabinkarpChecksum()}, nil
	default:
		return nil, fmt.Errorf("unexpected checksum type %#x", checksumType)
	}
}

func (c *Checksum) MaxStrongChecksumSize() uint32 {
	switch c.checksumType {
	case Rollsum_Md4, Rabinkarp_Md4:
		return Md4ChecksumMaxSize
	default:
		return Blake2bChecksumMaxSize
	}
}

func (c *Checksum) CalculateWeakChecksum(data []byte) uint32 {
	switch c.checksumType {
	case Rollsum_Md4, Rollsum_Blake2b:
		rc := NewRollingChecksum()
		rc.Update(data)
		return rc.Digest()
	default:
		rc := NewRabinkarpChecksum()
		rc.Update(data)
		return rc.Digest()
	}
}

func (c *Checksum) CalculateStrongChecksum(data []byte, checksumSize uint32) ([]byte, error) {
	var checksum []byte
	switch c.checksumType {
	case Rollsum_Md4, Rabinkarp_Md4:
		h := md4.New()
		h.Write(data)
		checksum = h.Sum(nil)
	default:
		s := blake2b.Sum256(data)
		checksum = s[:]
	}

	if len(checksum) < int(checksumSize) {
		return nil, fmt.Errorf("strong checksum size %d exceeds actual size %d for checksum type %#x", checksumSize, len(checksum), c.checksumType)
	}

	return checksum[:checksumSize], nil
}

func (c *Checksum) Rollin(in byte) {
	switch c.checksumType {
	case Rollsum_Md4, Rollsum_Blake2b:
		c.rollsum.Rollin(in)
	default:
		c.rabinkarp.Rollin(in)
	}
}

func (c *Checksum) Rollout(out byte) {
	switch c.checksumType {
	case Rollsum_Md4, Rollsum_Blake2b:
		c.rollsum.Rollout(out)
	default:
		c.rabinkarp.Rollout(out)
	}
}

func (c *Checksum) Digest() uint32 {
	switch c.checksumType {
	case Rollsum_Md4, Rollsum_Blake2b:
		return c.rollsum.Digest()
	default:
		return c.rabinkarp.Digest()
	}
}

func (c *Checksum) Reset() {
	switch c.checksumType {
	case Rollsum_Md4, Rollsum_Blake2b:
		c.rollsum.Reset()
	default:
		c.rabinkarp.Reset()
	}
}

func (c *Checksum) Count() uint64 {
	switch c.checksumType {
	case Rollsum_Md4, Rollsum_Blake2b:
		return c.rollsum.count
	default:
		return c.rabinkarp.count
	}
}
