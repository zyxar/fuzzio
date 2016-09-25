package fuzzio

import (
	"io"
)

type Reader struct {
	src    io.Reader
	cipher Cipher
	rdbuf  []byte // holding bytes read from src
	decbuf []byte // holding bytes decrypted from a whole rdbuf
	// head
	length uint32 // real length of message parsed from header
	blocks uint32 // number of blocks
	// read
	blkId  uint32 // current processing block id
	rIndex int    // bytes of rdbuf read from src
	wIndex int    // bytes of decbuf read by Read()
	flush  bool
}

func NewReader(src io.Reader, length uint32, cipher Cipher) io.Reader {
	r := &Reader{
		src:    src,
		cipher: cipher,
		rdbuf:  make([]byte, cipher.BlockSize()),
		decbuf: make([]byte, cipher.BlockSize()),
		length: length,
		blocks: length / uint32(cipher.BlockSize()),
	}
	return r
}

func (r *Reader) Read(buf []byte) (n int, err error) {
	if len(buf) == 0 {
		return
	}
	// flush remaining bytes
	if r.flush {
		n = copy(buf, r.decbuf[r.wIndex:])
		r.wIndex += n
		r.wIndex %= len(r.decbuf)
		if r.wIndex > 0 {
			r.flush = true
			return // buf not enough
		}
		r.blkId++
		r.flush = false
	}

	if r.blkId > r.blocks {
		err = io.EOF
		return
	}

	// now r.decbuf is clean, r.wIndex == 0
	var nr int
	for r.blkId < r.blocks {
		nr, err = io.ReadFull(r.src, r.rdbuf[r.rIndex:])
		if err != nil { // so if readfull is not accomplished, next read still tries
			r.rIndex += nr
			if r.rIndex < r.cipher.BlockSize() {
				return
			}
		} // otherwise readfull is done, reset index
		r.rIndex = 0
		r.cipher.Decrypt(r.decbuf, r.rdbuf)
		nr = copy(buf[n:], r.decbuf)
		n += nr
		if nr < r.cipher.BlockSize() {
			r.wIndex = nr
			r.flush = true // so next read will try flush decbuf first
			return
		}
		r.blkId++
	}

	// trailing block
	if size := int(r.length) % r.cipher.BlockSize(); size > 0 {
		nr, err = io.ReadFull(r.src, r.rdbuf[r.rIndex:])
		if err != nil { // so if readfull is not accomplished, next read still tries
			r.rIndex += nr
			if r.rIndex < r.cipher.BlockSize() {
				return
			}
		} // otherwise readfull is done, reset index
		r.rIndex = 0
		r.cipher.Decrypt(r.decbuf, r.rdbuf)
		r.decbuf = r.decbuf[:size]
		nr = copy(buf[n:], r.decbuf)
		n += nr
		if nr < size {
			r.wIndex = nr
			r.flush = true // so next read will try flush decbuf first
			return
		}
		r.blkId++
	}
	if err == nil {
		err = io.EOF
	}
	return
}
