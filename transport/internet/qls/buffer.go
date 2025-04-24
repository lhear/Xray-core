package qls

import (
	"math/bits"
	"sync"
)

const maxPoolSize = 65536

var poolSizes = []int{
	32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024,
	1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384,
	24576, 32768, 49152, 65536,
}

type DynamicBufferPool struct {
	pools map[int]*sync.Pool
}

func NewDynamicBufferPool() *DynamicBufferPool {
	p := &DynamicBufferPool{
		pools: make(map[int]*sync.Pool, len(poolSizes)),
	}

	for _, size := range poolSizes {
		currentSize := size
		p.pools[currentSize] = &sync.Pool{
			New: func() interface{} {
				b := make([]byte, 0, currentSize)
				return &b
			},
		}
	}
	return p
}

func ceilPowerOfTwo(n int) int {
	if n <= 0 {
		return 1
	}
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	if bits.UintSize == 64 {
		n |= n >> 32
	}
	n++
	return n
}

func findBestFitSize(n int) int {
	for _, size := range poolSizes {
		if n <= size {
			return size
		}
	}
	return ceilPowerOfTwo(n)
}

func (p *DynamicBufferPool) Get(size int) []byte {
	actualSize := findBestFitSize(size)

	if actualSize > maxPoolSize {
		return make([]byte, 0, actualSize)
	}

	pool, ok := p.pools[actualSize]
	if !ok {
		return make([]byte, 0, actualSize)
	}

	v := pool.Get()
	ptrBuf := v.(*[]byte)

	if ptrBuf == nil {
		b := make([]byte, 0, actualSize)
		return b
	}

	buf := *ptrBuf
	return buf
}

func (p *DynamicBufferPool) Put(buf []byte) {
	if buf == nil {
		return
	}

	size := cap(buf)

	pool, ok := p.pools[size]
	if !ok {
		return
	}

	buf = buf[:0]
	pool.Put(&buf)
}
