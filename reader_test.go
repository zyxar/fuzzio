package fuzzio

import (
	"bytes"
	"io"
	"testing"
)

func TestRead(t *testing.T) {
	var input = []byte{
		0x4A, 0x41, 0x5B, 0x8A, 0x56, 0xCF, 0xA7, 0x72,
		0x86, 0xF0, 0x25, 0x75, 0x34, 0x13, 0x25, 0x98, 0x00, // trailling one byte
	}
	var text = []byte{
		'H', 'E', 'L', 'L',
		'O', ' ', 'W', 'O',
		'R', 'L', 'D', '!',
		0x56, 0xCF, 0xA7, 0x72,
	}
	for i := 1; i < 32; i++ {
		for j := uint32(1); j < 17; j++ {
			rd := NewReader(bytes.NewReader(input), j, cipher)
			var dst bytes.Buffer
			buf := make([]byte, i)
			var err error
			var n int
			for err == nil {
				n, err = rd.Read(buf[:])
				dst.Write(buf[:n])
			}
			if err != nil && err != io.EOF {
				t.Errorf("[%02d, %02d] read error: %v", i, j, err)
			}
			var content = dst.Bytes()
			if bytes.Compare(content, text[:j]) != 0 {
				t.Errorf("[%02d, %02d] read error: %d, %#v", i, j, len(content), content)
			}
		}
	}
}
