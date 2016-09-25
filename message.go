package fuzzio

import (
	"bytes"
	"io"
)

type Message interface {
	io.WriterTo
	io.Writer
	io.ReaderFrom
	BlockSize() int
	Len() int
	String() string
	Bytes() []byte
	Truncate(n int)
	WriteByte(c byte) error
	WriteRune(r rune) (n int, err error)
	WriteString(s string) (n int, err error)
	Reset()
}

func NewMessage(cipher Cipher) Message {
	return &message{cipher: cipher}
}

type message struct {
	bytes.Buffer
	cipher Cipher
}

func (m *message) BlockSize() int {
	return m.cipher.BlockSize()
}

func (m *message) WriteTo(w io.Writer) (n int64, err error) {
	var h = Header(m.Buffer.Len())
	blockSize := m.BlockSize() // >= 8
	encbuf := make([]byte, blockSize)
	h.encode(encbuf, m.cipher)
	_, err = w.Write(encbuf) // header length is not included in n
	if err != nil {
		return
	}
	buf := make([]byte, blockSize)
	var nr int
	for m.Buffer.Len() > 0 {
		m.Read(buf) // assume read won't fail here
		m.cipher.Encrypt(encbuf, buf)
		nr, err = w.Write(encbuf)
		n += int64(nr)
		if err != nil {
			return
		}
	}
	return
}
