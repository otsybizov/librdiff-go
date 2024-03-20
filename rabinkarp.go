package rdiff

type RabinkarpChecksum struct {
	count            uint64
	hash, multiplier uint32
}

func NewRabinkarpChecksum() *RabinkarpChecksum {
	return &RabinkarpChecksum{
		count:      0,
		hash:       RabinkarpSeed,
		multiplier: 1,
	}
}

func (r *RabinkarpChecksum) Update(buf []byte) {
	length := len(buf)
	r.count += uint64(length)

	for i := 0; i < length; i++ {
		r.hash = r.hash*RabinkarpMultiplier + uint32(buf[i])
		r.multiplier *= RabinkarpMultiplier
	}
}

func (r *RabinkarpChecksum) Rotate(out, in byte) {
	r.hash = r.hash*RabinkarpMultiplier + uint32(in) - r.multiplier*(uint32(out)+RabinkarpAdjustment)
}

func (r *RabinkarpChecksum) Rollin(in byte) {
	r.hash = r.hash*RabinkarpMultiplier + uint32(in)
	r.count++
	r.multiplier *= RabinkarpMultiplier
}

func (r *RabinkarpChecksum) Rollout(out byte) {
	r.count--
	r.multiplier *= RabinkarpMultiplierInverseModular
	r.hash -= r.multiplier * (uint32(out) + RabinkarpAdjustment)
}

func (r *RabinkarpChecksum) Digest() uint32 {
	return r.hash
}

func (r *RabinkarpChecksum) Reset() {
	r.count = 0
	r.hash = RabinkarpSeed
	r.multiplier = 1
}
