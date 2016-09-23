package fuzzio

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	"github.com/zyxar/fuzzio/xtea_le"
)

var key = []byte{
	0x63, 0x04, 0xD8, 0x1C,
	0x85, 0x76, 0xB7, 0xCA,
	0xCB, 0xD9, 0xE1, 0x34,
	0xE8, 0xAE, 0xDE, 0x5A,
}

func TestKey(t *testing.T) {
	var b, d [8]byte
	binary.LittleEndian.PutUint64(b[:], 0x0102030405060708)
	ci, _ := xtea_le.NewCipher(key)
	ci.Encrypt(d[:], b[:])
	if bytes.Compare(d[:], []byte{0xE2, 0xBE, 0x32, 0xC8, 0xC8, 0xB9, 0xED, 0x42}) != 0 {
		t.Fatal("INVALID KEY or INVALID CIPHER!")
	}
}

func TestRead(t *testing.T) {
	src := bytes.NewReader([]byte{
		0xDC, 0xE9, 0x3B, 0x99, 0x72, 0x76, 0x65, 0x92,
		0x4A, 0x41, 0x5B, 0x8A, 0x56, 0xCF, 0xA7, 0x72,
		0x86, 0xF0, 0x25, 0x75, 0x34, 0x13, 0x25, 0x98,
	})
	cipher, _ := xtea_le.NewCipher(key)
	rd := NewReader(src, cipher)
	buf := make([]byte, 16)
	n, err := rd.Read(buf)
	if err != nil && err != io.EOF {
		t.Error(err)
	}
	if n != 12 {
		t.Fatalf("INVALID LENGTH %d", n)
	}
	fmt.Printf("%s\n", buf[:12])
}
