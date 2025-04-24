package qls

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/ascii85"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/crypto/hkdf"
)

const maxPayloadPerRecord = 65535 - 2 - 16

var bufferPool = NewDynamicBufferPool()

type qlsListener struct {
	net.Listener
	config *Config
}

type QLSConn struct {
	net.Conn
	aead          cipher.AEAD
	readNonce     [12]byte // 读取 nonce，使用 12 字节数组
	writeNonce    [12]byte // 写入 nonce，使用 12 字节数组
	handshakeDone bool
	readBuffer    []byte // 用于读取原始数据包的缓冲区，从池中获取
	decryptedData []byte // readBuffer 中已解密但尚未被读取的数据切片
}

func NewListener(listener net.Listener, config *Config) net.Listener {
	return &qlsListener{
		Listener: listener,
		config:   config,
	}
}

func (l *qlsListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		qlsConn, qlsErr := Server(context.Background(), conn, l.config)
		if qlsErr != nil {
			errors.LogWarning(context.Background(), qlsErr)
			continue
		}

		return qlsConn, nil
	}
}

// Client 创建一个新的 QLS 客户端连接。
func Client(ctx context.Context, conn net.Conn, config *Config) (qlsConn stat.Connection, err error) {
	// 初始化 12 字节 nonces (客户端发送使用 1，接收使用 2)
	clientWriteNonce := [12]byte{} // 全部为零
	clientWriteNonce[11] = 1       // 将最低有效字节设置为 1

	clientReadNonce := [12]byte{} // 全部为零
	clientReadNonce[11] = 2       // 将最低有效字节设置为 2

	tempConn := &QLSConn{ // 初始使用临时变量
		Conn:       conn,
		readNonce:  clientReadNonce,
		writeNonce: clientWriteNonce,
		readBuffer: nil, // 初始化为 nil
	}

	defer func() {
		// 如果发生了错误，释放缓冲区并关闭底层连接。
		if err != nil {
			if tempConn.readBuffer != nil {
				tempConn.readBuffer = nil
			}
			if conn != nil {
				conn.Close()
			}
		}
	}()

	// 1. 生成客户端 X25519 密钥对。
	clientPrivKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		err = fmt.Errorf("failed to generate X25519 key pair: %w", err)
		return
	}
	clientPubKey := clientPrivKey.PublicKey().Bytes() // 32 字节

	// 按照要求对客户端公钥的前 20 字节进行 Ascii85 编码
	var clientPubKeyPart1Encoded [25]byte
	encodedLen := ascii85.Encode(clientPubKeyPart1Encoded[:], clientPubKey[:20])

	// 获取客户端公钥的后 12 字节
	clientPubKeyPart2 := clientPubKey[20:] // 12 字节

	// 构造要发送的握手数据：编码后的前 20 字节 + 后 12 字节原始数据
	var clientHandshakeData [37]byte
	copy(clientHandshakeData[:encodedLen], clientPubKeyPart1Encoded[:encodedLen])
	copy(clientHandshakeData[encodedLen:], clientPubKeyPart2)

	// 设置握手超时
	conn.SetDeadline(time.Now().Add(time.Duration(config.HandshakeTimeout) * time.Millisecond))

	// 2. 发送客户端握手数据到服务器。
	if _, err = conn.Write(clientHandshakeData[:]); err != nil {
		err = fmt.Errorf("failed to send client handshake data: %w", err)
		return
	}

	// 3. 接收服务器的 X25519 公钥和签名。(总计 96 字节)
	// 服务器发送：x25519 公钥 (32 字节) + ed25519 签名 (64 字节)
	var serverHandshakeData [96]byte
	if _, err = io.ReadFull(conn, serverHandshakeData[:]); err != nil {
		err = fmt.Errorf("failed to receive server handshake data: %w", err)
		return
	}
	conn.SetDeadline(time.Time{}) // 清除超时

	serverPubKey := serverHandshakeData[:32]
	serverSignature := serverHandshakeData[32:]

	// 4. 使用 Ed25519 公钥验证服务器签名。
	// 签名是针对服务器的 X25519 公钥 (serverPubKey)。
	if len(config.PublicKey) != ed25519.PublicKeySize {
		err = fmt.Errorf("invalid Ed25519 public key size for verification")
		return
	}
	if !ed25519.Verify(ed25519.PublicKey(config.PublicKey), serverPubKey, serverSignature) {
		err = fmt.Errorf("server signature verification failed")
		return
	}

	// 5. 执行 X25519 密钥交换以获得共享密钥。
	serverX25519PubKeyECDH, err := ecdh.X25519().NewPublicKey(serverPubKey)
	if err != nil {
		err = fmt.Errorf("invalid server X25519 public key: %w", err)
		return
	}
	// clientPubKey 是本地生成的完整 32 字节公钥
	sharedSecret, err := clientPrivKey.ECDH(serverX25519PubKeyECDH)
	if err != nil {
		err = fmt.Errorf("X25519 key exchange failed: %w", err)
		return
	}

	// 6. 使用 HKDF-SHA256 派生最终密钥。
	var finalKey [32]byte
	kdf := hkdf.New(sha256.New, sharedSecret, append(clientPubKey, serverPubKey...), []byte("QLS-Derived-Key"))
	if _, err = io.ReadFull(kdf, finalKey[:]); err != nil {
		err = fmt.Errorf("failed to derive final key: %w", err)
		return
	}

	// 7. 为数据传输初始化 AES256-GCM AEAD。
	aesBlockData, err := aes.NewCipher(finalKey[:])
	if err != nil {
		err = fmt.Errorf("failed to create AES cipher for AEAD: %w", err)
		return
	}
	aeadData, err := cipher.NewGCM(aesBlockData)
	if err != nil {
		err = fmt.Errorf("failed to create AES-GCM AEAD for data transfer: %w", err)
		return
	}
	tempConn.aead = aeadData
	tempConn.handshakeDone = true
	errors.LogInfo(ctx, "handshake successful")

	return stat.Connection(tempConn), nil
}

// Server 创建一个新的 QLS 服务器连接。
func Server(ctx context.Context, conn net.Conn, config *Config) (qlsConn stat.Connection, err error) {
	// 初始化 12 字节 nonces (服务器接收使用 1，发送使用 2)
	serverReadNonce := [12]byte{} // 全部为零
	serverReadNonce[11] = 1       // 将最低有效字节设置为 1

	serverWriteNonce := [12]byte{} // 全部为零
	serverWriteNonce[11] = 2       // 将最低有效字节设置为 2

	tempConn := &QLSConn{ // 初始使用临时变量
		Conn:       conn,
		readNonce:  serverReadNonce,
		writeNonce: serverWriteNonce,
		readBuffer: nil, // 初始化为 nil
	}

	defer func() {
		// 如果发生了错误，释放缓冲区并关闭底层连接。
		if err != nil {
			if tempConn.readBuffer != nil {
				bufferPool.Put(tempConn.readBuffer)
				tempConn.readBuffer = nil
			}
			if conn != nil {
				conn.Close()
			}
		}
	}()

	// 确保提供的私钥是有效的 Ed25519 种子
	if len(config.PrivateKey) != ed25519.SeedSize {
		err = fmt.Errorf("invalid Ed25519 private key size (expected 32 bytes seed): invalid key size")
		return
	}
	serverEd25519PrivateKey := ed25519.NewKeyFromSeed(config.PrivateKey) // 从种子创建 Ed25519.PrivateKey

	// 1. 实现带有超时的读取，用于客户端的初始消息。
	// 客户端发送：Ascii85(客户端公钥前 20 字节) (25 字节) + 客户端公钥后 12 字节 (原始) (12 字节)。
	var clientHandshakeDataEncodedAndRaw [37]byte
	handshakeDeadline := time.Now().Add(time.Duration(config.HandshakeTimeout) * time.Millisecond)
	conn.SetDeadline(handshakeDeadline) // 设置握手超时

	// 读取客户端握手数据
	if _, err = io.ReadFull(conn, clientHandshakeDataEncodedAndRaw[:]); err != nil {
		err = fmt.Errorf("failed to read client handshake data: %w", err)
		return
	}

	// 分割数据：前 25 字节是编码的，后 12 字节是原始数据
	clientPubKeyPart1Encoded := clientHandshakeDataEncodedAndRaw[:25] // 25 字节
	clientPubKeyPart2 := clientHandshakeDataEncodedAndRaw[25:]        // 12 字节

	// 对前 25 字节进行 Ascii85 解码，得到原始的前 20 字节公钥
	var clientPubKeyPart1 [20]byte
	decodedLen, _, err := ascii85.Decode(clientPubKeyPart1[:], clientPubKeyPart1Encoded, true)
	if err != nil {
		io.Copy(io.Discard, conn)
		err = fmt.Errorf("failed to decode client public key part 1: %w", err)
		return
	}
	if decodedLen != 20 {
		io.Copy(io.Discard, conn)
		err = fmt.Errorf("decoded client public key part 1 has unexpected length. Declared: %d, Expected: %d", decodedLen, 20)
		return
	}

	// 解码后的前 20 字节 + 后 12 字节原始数据
	var clientX25519PubKey [32]byte
	copy(clientX25519PubKey[:20], clientPubKeyPart1[:])
	copy(clientX25519PubKey[20:], clientPubKeyPart2)
	clientX25519PubKeySlice := clientX25519PubKey[:]

	// 验证重构后的客户端公钥长度
	if len(clientX25519PubKeySlice) != 32 {
		io.Copy(io.Discard, conn)
		err = fmt.Errorf("reconstructed client public key has unexpected length. Declared: %d, Expected: %d", len(clientX25519PubKeySlice), 32)
		return
	}

	// 2. 生成服务器 X25519 密钥对。
	serverPrivKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		err = fmt.Errorf("failed to generate X25519 key pair: %w", err)
		return
	}
	serverPubKey := serverPrivKey.PublicKey().Bytes() // 32 字节

	// 3. 使用 Ed25519 私钥对服务器的 X25519 公钥进行签名。
	serverSignature := ed25519.Sign(serverEd25519PrivateKey, serverPubKey)

	// 4. 发送服务器的 X25519 公钥和签名到客户端。(总计 96(32+64) 字节)
	var serverHandshakeData [96]byte
	copy(serverHandshakeData[:32], serverPubKey)
	copy(serverHandshakeData[32:], serverSignature)
	serverHandshakeDataSlice := serverHandshakeData[:]

	if _, writeErr := conn.Write(serverHandshakeDataSlice); writeErr != nil {
		err = fmt.Errorf("failed to send server handshake data: %w", writeErr)
		return
	}
	conn.SetDeadline(time.Time{}) // 清除超时

	// 5. 执行 X25519 密钥交换以获得共享密钥。
	clientX25519PubKeyECDH, err := ecdh.X25519().NewPublicKey(clientX25519PubKeySlice)
	if err != nil {
		err = fmt.Errorf("invalid client X25519 public key after reconstruction: %w", err)
		return
	}
	sharedSecret, err := serverPrivKey.ECDH(clientX25519PubKeyECDH)
	if err != nil {
		err = fmt.Errorf("X25519 key exchange failed: %w", err)
		return
	}

	// 6. 使用 HKDF-SHA256 派生最终密钥。
	var finalKey [32]byte
	kdf := hkdf.New(sha256.New, sharedSecret, append(clientX25519PubKeySlice, serverPubKey...), []byte("QLS-Derived-Key"))
	if _, err = io.ReadFull(kdf, finalKey[:]); err != nil {
		err = fmt.Errorf("failed to derive final key: %w", err)
		return
	}

	// 7. 为数据传输初始化 AES256-GCM AEAD。
	aesBlockData, err := aes.NewCipher(finalKey[:])
	if err != nil {
		err = fmt.Errorf("failed to create AES cipher for AEAD for data transfer: %w", err)
		return
	}
	aeadData, err := cipher.NewGCM(aesBlockData)
	if err != nil {
		err = fmt.Errorf("failed to create AES-GCM AEAD for data transfer: %w", err)
		return
	}
	tempConn.aead = aeadData
	tempConn.handshakeDone = true
	errors.LogInfo(ctx, "handshake successful")

	return stat.Connection(tempConn), nil
}

// incrementNonce 为一个 12 字节的大端序 nonce 添加 2。
func incrementNonce(nonce [12]byte) [12]byte {
	// 将 12 字节的 nonce 视为一个大端序整数并加 2。
	// 从最低有效字节（索引 11）到最高有效字节（索引 0）迭代。
	carry := uint16(2)
	// 从要添加的值开始，初始进位为 2。

	for i := 11; i >= 0; i-- {
		// 将当前字节和进位相加
		sum := uint16(nonce[i]) + carry
		nonce[i] = byte(sum) // 求和的低 8 位是新的字节值。
		carry = sum >> 8     // 求和的高 8 位是新的进位（加 2 时只会是 0 或 1）。

		// 如果没有进位，则完成。
		if carry == 0 {
			break
		}
	}
	// 不处理超过 12 字节的溢出，预计不会发生。
	return nonce
}

// Read 从 QLS 连接读取数据。
func (c *QLSConn) Read(b []byte) (int, error) {
	if !c.handshakeDone {
		return 0, errors.New("handshake not done")
	}

	// 尝试从 decryptedData 切片中读取。
	if len(c.decryptedData) > 0 {
		n := copy(b, c.decryptedData)
		c.decryptedData = c.decryptedData[n:] // 通过切片移除已读部分
		if len(c.decryptedData) == 0 {
			bufferPool.Put(c.readBuffer)
			c.readBuffer = nil
		}
		return n, nil
	}

	// 如果 decryptedData 为空，从底层连接读取新数据包并处理。
	// 在读取新数据包之前，如果存在旧的 readBuffer，则将其放回池中。
	if c.readBuffer != nil {
		bufferPool.Put(c.readBuffer)
		c.readBuffer = nil
	}

	// 数据包结构：长度 (2 字节) + 密文 (+ Tag)
	// 读取长度 (2 字节)
	var lengthBytes [2]byte
	if _, err := io.ReadFull(c.Conn, lengthBytes[:]); err != nil {
		// 传播底层连接的 EOF 或其他读取错误。
		if err == io.EOF {
			return 0, io.EOF
		}
		return 0, errors.New("failed to read length").Base(err)
	}
	totalPayloadLen := binary.BigEndian.Uint16(lengthBytes[:])

	// 检查总载荷长度是否合理，防止读取超大或负数长度
	if 2+int(totalPayloadLen) > 65535 {
		return 0, errors.New("incoming packet payload length too large")
	}
	if totalPayloadLen < uint16(c.aead.Overhead()) { // 载荷至少要包含 Tag
		return 0, errors.New("incoming packet payload length too small")
	}

	// 获取一个足够大的缓冲区来读取密文和进行原地解密。
	// 缓冲区需要能容纳 2 字节长度 + 密文 + Tag。
	requiredBufferForPayload := int(totalPayloadLen)
	c.readBuffer = bufferPool.Get(requiredBufferForPayload)

	// 读取密文 (+ Tag)，长度为 totalPayloadLen
	ciphertextWithTagBufferSlice := c.readBuffer[:totalPayloadLen]
	if _, err := io.ReadFull(c.Conn, ciphertextWithTagBufferSlice); err != nil {
		// 传播底层连接的 EOF 或其他读取错误。
		bufferPool.Put(c.readBuffer)
		c.readBuffer = nil
		return 0, errors.New("failed to read payload (ciphertextWithTag)").Base(err)
	}

	// 使用 AEAD 解密，原地写入 readBuffer 的开始位置
	nonce := c.readNonce[:]

	// 构建 AAD: Nonce (12 bytes) + 刚刚读取的 Length (2 bytes)
	var aad [14]byte
	copy(aad[:12], nonce)
	copy(aad[12:], lengthBytes[:])

	// 准备目标切片 dst 用于原地解密。
	// 指向 c.readBuffer 的开始位置。
	dst := c.readBuffer

	// 使用 AEAD.Open 进行解密和认证。
	// Open 会将解密后的明文写入 dst 的底层数组，并返回一个指向明文的新切片。
	decryptedPlaintext, err := c.aead.Open(dst[:0], nonce, ciphertextWithTagBufferSlice, aad[:])
	if err != nil {
		// 如果解密或认证失败，返回错误。此时不递增 readNonce。
		// 如果解密失败，也需要将 readBuffer 放回池中
		bufferPool.Put(c.readBuffer)
		c.readBuffer = nil
		return 0, errors.New("AEAD decryption or authentication failed").Base(err)
	}

	// 解密和认证成功后，递增读取 nonce
	c.readNonce = incrementNonce(c.readNonce)

	// 更新 decryptedData 切片，指向 c.readBuffer 中新解密的数据
	c.decryptedData = decryptedPlaintext

	// 将解密后的数据从 decryptedData 复制到缓冲区 b
	n_copied := copy(b, c.decryptedData)
	c.decryptedData = c.decryptedData[n_copied:] // 通过切片移除已读部分

	if len(c.decryptedData) == 0 {
		bufferPool.Put(c.readBuffer)
		c.readBuffer = nil
	}

	// 返回复制到用户缓冲区的字节数
	return n_copied, nil
}

// Write 将数据写入 QLS 连接。
func (c *QLSConn) Write(b []byte) (int, error) {
	if !c.handshakeDone {
		return 0, errors.New("handshake not done")
	}
	// 记录发送长度
	sendLen := 0

	// 检查整个数据包（密文+Tag）是否超出最大允许大小 (uint16 限制)
	for 2+len(b)+c.aead.Overhead() > 65535 {
		n, err := c.write(b[:maxPayloadPerRecord])
		sendLen += n
		if err != nil {
			return sendLen, err
		}
		b = b[maxPayloadPerRecord:]
	}
	if len(b) > 0 {
		n, err := c.write(b)
		sendLen += n
		if err != nil {
			return sendLen, err
		}
	}
	return sendLen, nil
}

func (c *QLSConn) write(b []byte) (int, error) {
	// 数据包结构：长度 (2 字节) + 密文 (+ Tag)

	// Nonce 是结构体中 12 字节的自增 nonce
	nonce := c.writeNonce[:]

	// 计算预期的密文长度 (明文长度 + Tag 长度)
	expectedSealedLen := len(b) + c.aead.Overhead()
	// 检查整个数据包（密文+Tag）是否超出最大允许大小 (uint16 限制)
	if 2+expectedSealedLen > 65535 {
		panic("payload too large for packet (exceeds uint16 limit for length field)")
	}

	// 获取一个缓冲区用于构建数据包：2 字节长度 + 密文 + Tag
	// 缓冲区容量需要至少为 2 + expectedSealedLen。
	requiredBufferSize := 2 + expectedSealedLen
	writeBuffer := bufferPool.Get(requiredBufferSize)
	defer bufferPool.Put(writeBuffer) // 确保缓冲区被放回池中

	// 将密文长度编码为 2 字节，写入缓冲区的开始
	lengthBytes := writeBuffer[:2]
	binary.BigEndian.PutUint16(lengthBytes, uint16(expectedSealedLen)) // 编码预期的密封数据长度

	// 构建 AAD: Nonce (12 bytes) + Length (2 bytes)
	var aad [14]byte
	copy(aad[:12], nonce)
	copy(aad[12:], lengthBytes)

	// 使用 AEAD 加密，Nonce 和 AAD 包含长度字段
	// 目标切片在 writeBuffer 中，从索引 2 开始，容量足够容纳密封数据
	dst := writeBuffer[2 : 2+expectedSealedLen]

	// 调用 Seal，将加密数据写入 dst 的底层数组，并捕获返回的实际密封数据切片
	sealedData := c.aead.Seal(dst[:0], nonce, b, aad[:])

	// 构造完整数据包：2 字节长度 + 实际密封数据
	// 使用返回的 sealedData 切片来确定写入连接的准确数据范围
	packet := writeBuffer[:2+len(sealedData)]

	// 将数据包写入连接
	_, err := c.Conn.Write(packet)
	if err != nil {
		return 0, errors.New("failed to write packet").Base(err)
	}

	// 写入成功后递增写入 nonce
	c.writeNonce = incrementNonce(c.writeNonce)

	// 返回写入的原始明文长度
	return len(b), nil
}

// Close 关闭 QLS 连接。
func (c *QLSConn) Close() error {
	if c.readBuffer != nil {
		bufferPool.Put(c.readBuffer)
		c.readBuffer = nil
	}
	return c.Conn.Close()
}

// LocalAddr 返回本地网络地址。
func (c *QLSConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

// RemoteAddr 返回远程网络地址。
func (c *QLSConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

// SetDeadline 设置连接的读取和写入 deadline。
func (c *QLSConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

// SetReadDeadline 设置连接的读取 deadline。
func (c *QLSConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline 设置连接的写入 deadline。
func (c *QLSConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

// 实现 buf.Writer 接口
func (c *QLSConn) WriteMultiBuffer(mb buf.MultiBuffer) (err error) {
	defer buf.ReleaseMulti(mb)
	if !c.handshakeDone {
		return errors.New("handshake not done")
	}
	bufferCap := min(int(mb.Len()), maxPayloadPerRecord)
	buffer := bufferPool.Get(bufferCap)
	defer bufferPool.Put(buffer)

	currentLen := 0 // 追踪 buffer 的当前有效长度
	// 遍历 MultiBuffer 中的缓冲区
	for _, b := range mb {
		if b.IsEmpty() {
			continue // 跳过空缓冲区
		}

		bytesToCopy := b.Bytes()
		copyLen := len(bytesToCopy)

		// 检查容量是否足够
		if currentLen+copyLen > bufferCap {
			_, writeErr := c.Write(buffer)
			if writeErr != nil {
				err = errors.New("failed to write aggregated data").Base(writeErr)
				return
			}
			currentLen = 0
			buffer = buffer[:0]
		}

		// 复制到 buffer 的 currentLen 之后的位置
		n := copy(buffer[currentLen:currentLen+copyLen], bytesToCopy)

		// 更新 buffer 的实际长度
		currentLen += n
		buffer = buffer[:currentLen]
	}

	if len(buffer) == 0 {
		return nil
	}

	_, writeErr := c.Write(buffer)
	if writeErr != nil {
		err = errors.New("failed to write aggregated data").Base(writeErr)
		return
	}

	return nil
}
