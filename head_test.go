package fuzzio

import (
	"bytes"
	"testing"
)

func TestHead(t *testing.T) {
	var head = Header(0x08)
	var buf [8]byte
	head.encode(buf[:], cipher)
	if bytes.Compare(buf[:], []byte{0xb7, 0x6d, 0x9e, 0xd1, 0x95, 0xed, 0x6e, 0xb4}) != 0 {
		t.Errorf("unexpected encoded result: %x", buf)
	}
	if err := DecodeHeader(buf[:], cipher, &head); err != nil {
		t.Error(err)
	}
}
