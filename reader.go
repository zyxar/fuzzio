package fuzzio

import (
	"encoding/binary"
	"io"
)

type Reader struct {
	src    io.Reader
	cipher Cipher
	rdbuf  []byte // holding bytes read from src
	decbuf []byte // holding bytes decrypted from a whole rdbuf
	// head
	length uint64 // real length of message parsed from header
	blocks uint64 // number of blocks
	// read
	blkId  uint64 // current processing block id
	rIndex int    // bytes of rdbuf read from src
	wIndex int    // bytes of decbuf read by Read()
}

func NewReader(src io.Reader, cipher Cipher) *Reader {
	r := &Reader{
		src:    src,
		cipher: cipher,
		rdbuf:  make([]byte, cipher.BlockSize()),
		decbuf: make([]byte, cipher.BlockSize()),
	}
	if err := r.readHead(); err != nil {
		return nil
	}
	return r
}

func (r *Reader) readHead() error {
	_, err := io.ReadFull(r.src, r.rdbuf)
	if err != nil {
		return err
	}
	r.cipher.Decrypt(r.decbuf, r.rdbuf)
	r.length = binary.LittleEndian.Uint64(r.decbuf)
	r.blocks = r.length / uint64(r.cipher.BlockSize())
	return nil
}

func (r *Reader) Read(buf []byte) (n int, err error) {
	if len(buf) == 0 {
		return
	}
	// flush remaining bytes
	if r.wIndex > 0 {
		n = copy(buf, r.decbuf[r.wIndex:])
		r.wIndex += n
		r.wIndex %= r.cipher.BlockSize()
		if r.wIndex > 0 {
			return // buf not enough
		}
		r.blkId++
	}
	// now r.decbuf is clean, r.wIndex == 0
	var nr int
	for r.blkId < r.blocks {
		nr, err = io.ReadFull(r.src, r.rdbuf[r.rIndex:])
		if err != nil { // so if readfull is not accomplished, next read still tries
			r.rIndex += nr
			return
		} // otherwise readfull is done, reset index
		r.rIndex = 0
		r.cipher.Decrypt(r.decbuf, r.rdbuf)
		nr = copy(buf[n:], r.decbuf)
		n += nr
		if nr < r.cipher.BlockSize() {
			r.wIndex = nr
			return // so next read will try flush decbuf first
		}
		r.blkId++
	}

	// trailing block
	if size := int(r.length) % r.cipher.BlockSize(); size > 0 {
		nr, err = io.ReadFull(r.src, r.rdbuf[r.rIndex:])
		if err != nil { // so if readfull is not accomplished, next read still tries
			r.rIndex += nr
			return
		} // otherwise readfull is done, reset index
		r.rIndex = 0
		r.cipher.Decrypt(r.decbuf, r.rdbuf)
		nr = copy(buf[n:], r.decbuf[:size])
		n += nr
		if nr < size {
			r.wIndex = nr
			return // so next read will try flush decbuf first
		}
		// r.blkId++
	}
	err = io.EOF
	return
}
