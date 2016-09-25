package fuzzio

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/zyxar/fuzzio/xtea_le"
)

var (
	cipher Cipher
	key    = []byte{
		0x63, 0x04, 0xD8, 0x1C,
		0x85, 0x76, 0xB7, 0xCA,
		0xCB, 0xD9, 0xE1, 0x34,
		0xE8, 0xAE, 0xDE, 0x5A}
	text = []byte{
		'H', 'E', 'L', 'L',
		'O', ' ', 'W', 'O',
		'R', 'L', 'D', '!',
		0x56, 0xCF, 0xA7, 0x72}
)

func init() {
	cipher, _ = xtea_le.NewCipher(key)
}

func TestKey(t *testing.T) {
	var b, d [8]byte
	binary.LittleEndian.PutUint64(b[:], 0x0102030405060708)
	cipher.Encrypt(d[:], b[:])
	if bytes.Compare(d[:], []byte{0xE2, 0xBE, 0x32, 0xC8, 0xC8, 0xB9, 0xED, 0x42}) != 0 {
		t.Fatal("INVALID KEY or INVALID CIPHER!")
	}
}
