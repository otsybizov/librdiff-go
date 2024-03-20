package rdiff

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRollingChecksum(t *testing.T) {
	r := NewRollingChecksum()
	assert.Equal(t, uint32(0x00000000), r.Digest())

	r.Rollin(0)
	assert.Equal(t, uint32(0x001f001f), r.Digest())
	r.Rollin(1)
	r.Rollin(2)
	r.Rollin(3)
	assert.Equal(t, uint32(0x01400082), r.Digest())

	r.Rotate(0, 4)
	assert.Equal(t, uint32(0x014a0086), r.Digest())
	r.Rotate(1, 5)
	r.Rotate(2, 6)
	r.Rotate(3, 7)
	assert.Equal(t, uint32(0x01680092), r.Digest())

	r.Rollout(4)
	assert.Equal(t, uint32(0x00dc006f), r.Digest())
	r.Rollout(5)
	r.Rollout(6)
	r.Rollout(7)
	assert.Equal(t, uint32(0x00000000), r.Digest())

	buf := make([]byte, 0, 256)
	for i := 0; i < 256; i++ {
		buf = append(buf, byte(i))
	}
	r.Update(buf)
	assert.Equal(t, uint32(0x3a009e80), r.Digest())
}
