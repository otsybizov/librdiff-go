package rdiff

type RollingChecksum struct {
	count  uint64
	s1, s2 uint16
}

func NewRollingChecksum() *RollingChecksum {
	return &RollingChecksum{}
}

func (r *RollingChecksum) Update(buf []byte) {
	length := len(buf)

	for i := 0; i < length; i++ {
		r.s1 += uint16(buf[i])
		r.s2 += r.s1
	}

	r.s1 += uint16(length) * RollingChecksumCharOffset
	r.s2 += uint16((length*(length+1))/2) * RollingChecksumCharOffset
	r.count += uint64(length)
}

func (r *RollingChecksum) Rotate(out, in byte) {
	r.s1 += uint16(in) - uint16(out)
	r.s2 += r.s1 - uint16(r.count)*(uint16(out)+RollingChecksumCharOffset)
}

func (r *RollingChecksum) Rollin(in byte) {
	r.s1 += uint16(in) + RollingChecksumCharOffset
	r.s2 += r.s1
	r.count += 1
}

func (r *RollingChecksum) Rollout(out byte) {
	r.s1 -= uint16(out) + RollingChecksumCharOffset
	r.s2 -= uint16(r.count) * (uint16(out) + RollingChecksumCharOffset)
	r.count -= 1
}

func (r *RollingChecksum) Digest() uint32 {
	return (uint32(r.s2) << 16) | (uint32(r.s1) & 0xffff)
}

func (r *RollingChecksum) Reset() {
	r.count = 0
	r.s1 = 0
	r.s2 = 0
}
