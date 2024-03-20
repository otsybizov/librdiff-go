package rdiff

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRabinkarpChecksum(t *testing.T) {
	r := NewRabinkarpChecksum()
	assert.Equal(t, uint32(0x00000001), r.Digest())

	r.Rollin(0)
	assert.Equal(t, uint32(0x08104225), r.Digest())
	r.Rollin(1)
	r.Rollin(2)
	r.Rollin(3)
	assert.Equal(t, uint32(0xaf981e97), r.Digest())

	r.Rotate(0, 4)
	assert.Equal(t, uint32(0xe2ef15f3), r.Digest())
	r.Rotate(1, 5)
	r.Rotate(2, 6)
	r.Rotate(3, 7)
	assert.Equal(t, uint32(0x7cf3fc07), r.Digest())

	r.Rollout(4)
	assert.Equal(t, uint32(0xf284a77f), r.Digest())
	r.Rollout(5)
	r.Rollout(6)
	r.Rollout(7)
	assert.Equal(t, uint32(0x00000001), r.Digest())

	buf := make([]byte, 0, 256)
	for i := 0; i < 256; i++ {
		buf = append(buf, byte(i))
	}
	r.Update(buf)
	assert.Equal(t, uint32(0xc1972381), r.Digest())
}
