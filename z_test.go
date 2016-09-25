package fuzzio

import (
	"bytes"
	"io"
	"testing"
)

func TestReaderWithHeader(t *testing.T) {
	input := []byte{
		0xB4, 0xD3, 0x18, 0x8A, 0x07, 0x92, 0x99, 0x6F,
		0x4A, 0x41, 0x5B, 0x8A, 0x56, 0xCF, 0xA7, 0x72,
		0x86, 0xF0, 0x25, 0x75, 0x34, 0x13, 0x25, 0x98, 0x00, // trailling one byte
	}
	src := bytes.NewReader(input)
	var head Header
	var buf [8]byte
	_, err := io.ReadFull(src, buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if err = DecodeHeader(buf[:], cipher, &head); err != nil {
		t.Fatal(err)
	}
	rd := NewReader(src, head.ContentLength(), cipher)
	var dst bytes.Buffer
	var n int
	for err == nil {
		n, err = rd.Read(buf[:])
		dst.Write(buf[:n])
	}
	if err != nil && err != io.EOF {
		t.Errorf("read error: %v", err)
	}
	var content = dst.Bytes()
	if bytes.Compare(content, text[:12]) != 0 {
		t.Errorf("read error: %d, %#v", len(content), content)
	}
}
