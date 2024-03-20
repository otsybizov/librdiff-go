package rdiff

const (
	// DeltaMagicNumber is a number written at the start of delta files.
	DeltaMagicNumber uint32 = 0x72730236

	// Md4ChecksumMaxSize is the max size in bytes of MD4 strong checksum
	Md4ChecksumMaxSize uint32 = 16

	// Blake2bChecksumMaxSize is the max size in bytes of BLAKE2B strong checksum
	Blake2bChecksumMaxSize uint32 = 32

	// RollingChecksumCharOffset is a prime number to improve the checksum algorithm
	RollingChecksumCharOffset uint16 = 31

	// RabinkarpSeed ensures different length zero blocks have different hashes. It
	// effectively encodes the length into the hash.
	RabinkarpSeed uint32 = 1

	// RabinkarpMultiplier has a bit pattern of 1's getting sparser with significance,
	// is the product of 2 large primes, and matches the characteristics for a good
	// LCG multiplier.
	RabinkarpMultiplier uint32 = 0x08104225

	// RabinkarpMultiplierInverseModular is the inverse of RABINKARP_MULT modular 2^32.
	// Multiplying by this is equivalent to dividing by RabinkarpMultiplier.
	RabinkarpMultiplierInverseModular uint32 = 0x98f009ad

	// RabinkarpAdjustment is a factor used to adjust for the seed when rolling out values.
	// It's equal to; (RabinkarpMultiplier - 1) * RabinkarpSeed
	RabinkarpAdjustment uint32 = 0x08104224

	// MinParameterizedLiteralCommand is the minimum literal command code with dynamic size set as parameter.
	MinParameterizedLiteralCommand byte = 65

	// MinCopyCommand is the minimum copy command code.
	MinCopyCommand byte = 69

	// MinReservedCommand is the minimum reserved command code.
	MinReservedCommand byte = 85
)

type ChecksumType uint32

const (
	Rollsum_Md4       ChecksumType = 0x72730136
	Rollsum_Blake2b   ChecksumType = 0x72730137
	Rabinkarp_Md4     ChecksumType = 0x72730146
	Rabinkarp_Blake2b ChecksumType = 0x72730147
)

type CommandType byte

const (
	End CommandType = iota
	Literal
	Copy
	Reserved
)
