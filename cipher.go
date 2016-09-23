package fuzzio

type Cipher interface {
	Decrypt(dst, src []byte)
	Encrypt(dst, src []byte)
	BlockSize() int
}
