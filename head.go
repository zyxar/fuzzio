package fuzzio

import (
	"encoding/binary"
	"errors"
)

type Header uint32

func (h Header) encode(buf []byte, cipher Cipher) {
	var b [8]byte
	binary.LittleEndian.PutUint32(b[:4], magicFuzz)
	binary.LittleEndian.PutUint32(b[4:], uint32(h))
	cipher.Encrypt(buf, b[:])
	return
}

func (h Header) ContentLength() uint32 {
	return uint32(h)
}

func DecodeHeader(buf []byte, cipher Cipher, h *Header) error {
	if len(buf) < 8 {
		return ErrInvalidHeaderLen
	}
	var b [8]byte
	cipher.Decrypt(b[:], buf[:8])
	magic := binary.LittleEndian.Uint32(b[:4])
	if magic != magicFuzz {
		return ErrInvalidMagic
	}
	*h = Header(binary.LittleEndian.Uint32(b[4:]))
	return nil
}

const (
	magicFuzz uint32 = 0x7A7A662E // ".fzz"
)

var (
	ErrInvalidHeaderLen = errors.New("invalid fuzz header length")
	ErrInvalidMagic     = errors.New("invalid fuzz format")
)
