package qls

import (
	"math/bits" // 使用 math/bits 获取更高效的位运算
	"sync"
)

// 定义预分配池的最大容量
const maxPoolSize = 65536 // 64 KiB

// DynamicBufferPool 动态字节切片缓冲池，为高性能场景优化。
// 预先分配 2 的幂次大小的池，直到 maxPoolSize。
type DynamicBufferPool struct {
	pools map[int]*sync.Pool
}

// NewDynamicBufferPool 创建一个新的预分配、高性能的动态缓冲池。
func NewDynamicBufferPool() *DynamicBufferPool {
	p := &DynamicBufferPool{
		pools: make(map[int]*sync.Pool),
	}

	// 预分配从 32 到 maxPoolSize 的所有 2 的幂次池
	for size := 32; size <= maxPoolSize; size <<= 1 {
		// 使用闭包捕获当前的 size 值
		currentSize := size
		p.pools[currentSize] = &sync.Pool{
			New: func() interface{} {
				// 分配一个长度为 0，容量为 currentSize 的切片
				b := make([]byte, 0, currentSize)
				return &b // 返回切片的指针
			},
		}
	}
	return p
}

// ceilPowerOfTwo 计算大于或等于 n 的最小 2 的幂次。
// 兼容 Go 1.18 之前的版本。
func ceilPowerOfTwo(n int) int {
	if n <= 0 {
		return 1 // 根据 bits.CeilPowerOfTwo(0) == 1 的行为
	}
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	if bits.UintSize == 64 { // 处理 64 位系统
		n |= n >> 32
	}
	n++
	return n
}

// Get 从池中获取一个字节切片。
// 容量将是大于或等于指定 size 的最小 2 的幂次。
// 如果计算出的容量大于 maxPoolSize，则直接分配一个新的切片。
func (p *DynamicBufferPool) Get(size int) []byte {
	// 使用兼容的实现替换 bits.CeilPowerOfTwo
	actualSize := ceilPowerOfTwo(size)
	// 注意：bits.CeilPowerOfTwo(0) 返回 1，所以不需要检查 actualSize == 0
	// if actualSize == 0 {
	// 	 return nil
	// }

	// 如果请求的大小计算出的容量大于预分配池的范围，直接分配
	if actualSize > maxPoolSize {
		// 分配一个容量至少为 size 的新切片
		// 使用 actualSize 可以保持容量为 2 的幂次的特性
		return make([]byte, 0, actualSize)
	}

	// 从预分配的池中查找 (无需锁)
	pool, ok := p.pools[actualSize]
	if !ok {
		// 对于小于等于 maxPoolSize 的 2 的幂次，pool 应该总是存在
		// 但如果 ceilPowerOfTwo 返回了非预期的值（例如 1, 2, 4, 8, 16），
		// 则可能找不到，需要处理。
		// 为了安全起见，如果找不到池（虽然理论上不应该），则直接分配。
		return make([]byte, 0, actualSize)
	}

	v := pool.Get()
	ptrBuf := v.(*[]byte) // 断言为 *[]byte

	if ptrBuf == nil {
		b := make([]byte, 0, actualSize)
		return b
	}

	buf := *ptrBuf
	return buf
}

// Put 将一个字节切片返回给池。
// 只有容量是预分配范围内（<= maxPoolSize）的 2 的幂次的缓冲区才会被放回。
// 其他缓冲区将被忽略（由 GC 处理）。
func (p *DynamicBufferPool) Put(buf []byte) {
	if buf == nil {
		return
	}

	size := cap(buf)

	// 检查容量是否是有效的、在预分配范围内的 2 的幂次
	// 注意：池从 32 开始预分配
	if size < 32 || size > maxPoolSize || (size&(size-1)) != 0 {
		// 容量无效或超出范围，不放回池中
		return
	}

	// 查找对应的池 (无需锁)
	pool, ok := p.pools[size] // 使用 map 的并发安全读取特性
	if !ok {
		// 如果找不到池，说明容量不在预分配的 map 中，忽略
		return
	}

	// 重置长度并将指针放回池中
	buf = buf[:0]
	pool.Put(&buf)
}
