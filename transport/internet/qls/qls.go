package qls

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/ascii85"
	"encoding/binary"
	"hash"
	"io"
	"net"
	"time"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/hybrid"
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/crypto/hkdf"
)

const (
	maxPayloadPerRecord         = maxPoolSize
	labelClientHandshakeTraffic = "c hs traffic"
	labelServerHandshakeTraffic = "s hs traffic"
	labelClientAppTraffic       = "c ap traffic"
	labelServerAppTraffic       = "s ap traffic"
	handshakeSalt               = "QLS-Salt-v1"
)

var bufferPool = NewDynamicBufferPool()

type qlsListener struct {
	net.Listener
	config *Config
}

type QLSConn struct {
	net.Conn
	writeAEAD     cipher.AEAD
	readAEAD      cipher.AEAD
	readNonce     [12]byte
	writeNonce    [12]byte
	handshakeDone bool
	readBuffer    []byte
	decryptedData []byte
	writeCount    uint8
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

type handshakeState struct {
	conn          net.Conn
	config        *Config
	transcript    hash.Hash
	mlKemScheme   kem.Scheme
	mlDsaScheme   sign.Scheme
	localMlKemPk  kem.PublicKey
	localMlKemSk  kem.PrivateKey
	remoteMlKemPk []byte
	mlDsaPk       sign.PublicKey
	mlDsaSk       sign.PrivateKey
	sharedSecret  []byte
}

func newHandshakeState(conn net.Conn, config *Config) *handshakeState {
	mlKemScheme := hybrid.X25519MLKEM768()
	mlDsaScheme := mldsa65.Scheme()

	return &handshakeState{
		conn:        conn,
		config:      config,
		transcript:  sha256.New(),
		mlKemScheme: mlKemScheme,
		mlDsaScheme: mlDsaScheme,
	}
}

func (hs *handshakeState) generateLocalKeys() error {
	if len(hs.config.PrivateKey) > 0 {
		mlDsaSk, err := hs.mlDsaScheme.UnmarshalBinaryPrivateKey(hs.config.PrivateKey)
		if err != nil {
			return errors.New("failed to load ML-DSA private key").Base(err)
		}
		mlDsaPk := mlDsaSk.Public().(*mldsa65.PublicKey)
		hs.mlDsaPk = mlDsaPk
		hs.mlDsaSk = mlDsaSk
		hs.localMlKemPk = nil
		hs.localMlKemSk = nil
	} else {
		pk, sk, err := hs.mlKemScheme.GenerateKeyPair()
		if err != nil {
			return errors.New("failed to generate ML-KEM-768 key pair").Base(err)
		}
		hs.localMlKemPk = pk
		hs.localMlKemSk = sk

		mlDsaPk, err := hs.mlDsaScheme.UnmarshalBinaryPublicKey(hs.config.PublicKey)
		if err != nil {
			return errors.New("failed to load ML-DSA public key").Base(err)
		}
		hs.mlDsaPk = mlDsaPk
	}

	return nil
}

func (hs *handshakeState) sendClientHello() error {
	clientRandom := make([]byte, 32)
	if _, err := rand.Read(clientRandom); err != nil {
		return errors.New("failed to generate client random").Base(err)
	}

	encodedRandom := make([]byte, ascii85.MaxEncodedLen(len(clientRandom)))
	encodedLen := ascii85.Encode(encodedRandom, clientRandom)
	encodedRandom = encodedRandom[:encodedLen]

	clientMlKemPkBytes, err := hs.localMlKemPk.MarshalBinary()
	if err != nil {
		return errors.New("failed to marshal client ML-KEM-768 public key").Base(err)
	}

	clientHello := append(encodedRandom, clientMlKemPkBytes...)

	hs.transcript.Write(clientHello)
	if _, err := hs.conn.Write(clientHello); err != nil {
		return errors.New("failed to send ClientHello").Base(err)
	}
	return nil
}

func (hs *handshakeState) readClientHello() error {
	clientHelloSize := 40 + hs.mlKemScheme.PublicKeySize()
	clientHello := make([]byte, clientHelloSize)
	if _, err := io.ReadFull(hs.conn, clientHello); err != nil {
		return errors.New("failed to read ClientHello").Base(err)
	}
	hs.transcript.Write(clientHello)

	encodedRandom := clientHello[:40]
	clientRandom := make([]byte, 32)
	if _, _, err := ascii85.Decode(clientRandom, encodedRandom, true); err != nil {
		return errors.New("failed to decode client random").Base(err)
	}

	hs.remoteMlKemPk = clientHello[40:]
	return nil
}

func (hs *handshakeState) sendServerHello() error {
	serverRandom := make([]byte, 32)
	if _, err := rand.Read(serverRandom); err != nil {
		return errors.New("failed to generate server random").Base(err)
	}

	clientMlKemPk, err := hs.mlKemScheme.UnmarshalBinaryPublicKey(hs.remoteMlKemPk)
	if err != nil {
		return errors.New("failed to unmarshal client ML-KEM-768 public key").Base(err)
	}

	encapSeed := make([]byte, hs.mlKemScheme.EncapsulationSeedSize())
	if _, err := rand.Read(encapSeed); err != nil {
		return errors.New("failed to generate encapsulation seed").Base(err)
	}

	ciphertext, sharedSecret, err := hs.mlKemScheme.EncapsulateDeterministically(clientMlKemPk, encapSeed)
	if err != nil {
		return errors.New("ML-KEM-768 encapsulation failed").Base(err)
	}

	hs.sharedSecret = sharedSecret

	serverHello := append(serverRandom, ciphertext...)

	hs.transcript.Write(serverHello)
	if _, err := hs.conn.Write(serverHello); err != nil {
		return errors.New("failed to send ServerHello").Base(err)
	}
	return nil
}

func (hs *handshakeState) readServerHello() error {
	serverHelloSize := 32 + hs.mlKemScheme.CiphertextSize()
	serverHello := make([]byte, serverHelloSize)
	if _, err := io.ReadFull(hs.conn, serverHello); err != nil {
		return errors.New("failed to read ServerHello").Base(err)
	}
	hs.transcript.Write(serverHello)

	ciphertextStart := 32
	ciphertext := serverHello[ciphertextStart:]

	sharedSecret, err := hs.mlKemScheme.Decapsulate(hs.localMlKemSk, ciphertext)
	if err != nil {
		return errors.New("ML-KEM-768 decapsulation failed").Base(err)
	}

	hs.sharedSecret = sharedSecret
	return nil
}

func (hs *handshakeState) readAndVerifyServerSignature(serverHandshakeAEAD cipher.AEAD) error {
	var sigLenBytes [2]byte
	if _, err := io.ReadFull(hs.conn, sigLenBytes[:]); err != nil {
		return errors.New("failed to read signature length").Base(err)
	}
	sigLen := binary.BigEndian.Uint16(sigLenBytes[:])
	encryptedSignature := make([]byte, sigLen)
	if _, err := io.ReadFull(hs.conn, encryptedSignature); err != nil {
		return errors.New("failed to read encrypted signature").Base(err)
	}

	handshakeHash := hs.transcript.Sum(nil)
	serverNonce := [12]byte{}

	signature, err := serverHandshakeAEAD.Open(nil, serverNonce[:], encryptedSignature, handshakeHash)
	if err != nil {
		return errors.New("failed to decrypt server signature").Base(err)
	}

	if !hs.mlDsaScheme.Verify(hs.mlDsaPk, handshakeHash, signature, nil) {
		return errors.New("server ML-DSA signature verification failed")
	}
	return nil
}

func (hs *handshakeState) sendServerSignature(serverHandshakeAEAD cipher.AEAD) error {
	handshakeHash := hs.transcript.Sum(nil)

	signature := hs.mlDsaScheme.Sign(hs.mlDsaSk, handshakeHash, nil)

	serverNonce := [12]byte{}
	encryptedSignature := serverHandshakeAEAD.Seal(nil, serverNonce[:], signature, handshakeHash)

	var sigLenBytes [2]byte
	binary.BigEndian.PutUint16(sigLenBytes[:], uint16(len(encryptedSignature)))
	if _, err := hs.conn.Write(sigLenBytes[:]); err != nil {
		return errors.New("failed to send signature length").Base(err)
	}
	if _, err := hs.conn.Write(encryptedSignature); err != nil {
		return errors.New("failed to send encrypted signature").Base(err)
	}
	return nil
}

func Client(ctx context.Context, conn net.Conn, config *Config) (qlsConn stat.Connection, err error) {
	tempConn := &QLSConn{Conn: conn}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	hs := newHandshakeState(conn, config)

	if err = hs.generateLocalKeys(); err != nil {
		return nil, err
	}
	if err = hs.sendClientHello(); err != nil {
		return nil, err
	}

	if err = hs.readServerHello(); err != nil {
		return nil, err
	}

	handshakeHash := hs.transcript.Sum(nil)
	_, serverHandshakeAEAD, clientAppAEAD, serverAppAEAD, err := deriveKeys(hs.sharedSecret, handshakeHash)
	if err != nil {
		return nil, err
	}

	if err = hs.readAndVerifyServerSignature(serverHandshakeAEAD); err != nil {
		return nil, err
	}

	tempConn.writeAEAD = clientAppAEAD
	tempConn.readAEAD = serverAppAEAD
	tempConn.handshakeDone = true

	errors.LogInfo(ctx, "handshake successful")
	return stat.Connection(tempConn), nil
}

func Server(ctx context.Context, conn net.Conn, config *Config) (qlsConn stat.Connection, err error) {
	tempConn := &QLSConn{Conn: conn}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	if config.HandshakeTimeout > 0 {
		conn.SetDeadline(time.Now().Add(time.Duration(config.HandshakeTimeout) * time.Millisecond))
	} else {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
	}
	defer conn.SetDeadline(time.Time{})

	hs := newHandshakeState(conn, config)

	if err = hs.readClientHello(); err != nil {
		return nil, err
	}

	if err = hs.generateLocalKeys(); err != nil {
		return nil, err
	}
	if err = hs.sendServerHello(); err != nil {
		return nil, err
	}

	handshakeHash := hs.transcript.Sum(nil)
	_, serverHandshakeAEAD, clientAppAEAD, serverAppAEAD, err := deriveKeys(hs.sharedSecret, handshakeHash)
	if err != nil {
		return nil, err
	}

	if err = hs.sendServerSignature(serverHandshakeAEAD); err != nil {
		return nil, err
	}

	tempConn.readAEAD = clientAppAEAD
	tempConn.writeAEAD = serverAppAEAD
	tempConn.handshakeDone = true

	errors.LogInfo(ctx, "handshake successful")
	return stat.Connection(tempConn), nil
}

func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	fullLabel := "qls13 " + label
	labelBytes := []byte(fullLabel)

	info := make([]byte, 2+1+len(labelBytes)+1+len(context))
	binary.BigEndian.PutUint16(info[0:], uint16(length))
	info[2] = byte(len(labelBytes))
	copy(info[3:], labelBytes)
	info[3+len(labelBytes)] = byte(len(context))
	copy(info[4+len(labelBytes):], context)

	r := hkdf.Expand(sha256.New, secret, info)
	out := make([]byte, length)
	io.ReadFull(r, out)
	return out
}

func deriveKeys(sharedSecret, transcriptHash []byte) (cipher.AEAD, cipher.AEAD, cipher.AEAD, cipher.AEAD, error) {
	earlySecret := hkdf.Extract(sha256.New, sharedSecret, []byte(handshakeSalt))
	clientHandshakeSecret := hkdfExpandLabel(earlySecret, labelClientHandshakeTraffic, transcriptHash, 32)
	serverHandshakeSecret := hkdfExpandLabel(earlySecret, labelServerHandshakeTraffic, transcriptHash, 32)

	derivedSecret := hkdfExpandLabel(earlySecret, "derived", nil, 32)
	masterSecret := hkdf.Extract(sha256.New, nil, derivedSecret)
	clientAppSecret := hkdfExpandLabel(masterSecret, labelClientAppTraffic, transcriptHash, 32)
	serverAppSecret := hkdfExpandLabel(masterSecret, labelServerAppTraffic, transcriptHash, 32)

	clientHandshakeAEAD, err := newAEAD(clientHandshakeSecret)
	if err != nil {
		return nil, nil, nil, nil, errors.New("failed to create client handshake AEAD").Base(err)
	}
	serverHandshakeAEAD, err := newAEAD(serverHandshakeSecret)
	if err != nil {
		return nil, nil, nil, nil, errors.New("failed to create server handshake AEAD").Base(err)
	}
	clientAppAEAD, err := newAEAD(clientAppSecret)
	if err != nil {
		return nil, nil, nil, nil, errors.New("failed to create client application AEAD").Base(err)
	}
	serverAppAEAD, err := newAEAD(serverAppSecret)
	if err != nil {
		return nil, nil, nil, nil, errors.New("failed to create server application AEAD").Base(err)
	}

	return clientHandshakeAEAD, serverHandshakeAEAD, clientAppAEAD, serverAppAEAD, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func incrementNonce(nonce [12]byte) [12]byte {
	counter := binary.BigEndian.Uint64(nonce[4:])
	counter++
	binary.BigEndian.PutUint64(nonce[4:], counter)
	if counter == 0 {
		binary.BigEndian.PutUint32(nonce[0:4], binary.BigEndian.Uint32(nonce[0:4])+1)
	}
	return nonce
}

func (c *QLSConn) Read(b []byte) (int, error) {
	if !c.handshakeDone {
		return 0, errors.New("handshake not done")
	}

	if len(c.decryptedData) > 0 {
		n := copy(b, c.decryptedData)
		c.decryptedData = c.decryptedData[n:]
		if len(c.decryptedData) == 0 {
			bufferPool.Put(c.readBuffer)
			c.readBuffer = nil
		}
		return n, nil
	}

	if err := c.readRecord(); err != nil {
		return 0, err
	}

	n := copy(b, c.decryptedData)
	c.decryptedData = c.decryptedData[n:]

	if len(c.decryptedData) == 0 {
		bufferPool.Put(c.readBuffer)
		c.readBuffer = nil
	}

	return n, nil
}

func (c *QLSConn) readRecord() error {
	if c.readBuffer != nil {
		bufferPool.Put(c.readBuffer)
		c.readBuffer = nil
	}

	var lengthBytes [2]byte
	if _, err := io.ReadFull(c.Conn, lengthBytes[:]); err != nil {
		return err
	}
	payloadLen := binary.BigEndian.Uint16(lengthBytes[:])

	if payloadLen > maxPayloadPerRecord || payloadLen < uint16(c.readAEAD.Overhead()) {
		return errors.New("invalid incoming packet length")
	}

	c.readBuffer = bufferPool.Get(int(payloadLen))
	ciphertextWithTag := c.readBuffer[:payloadLen]
	if _, err := io.ReadFull(c.Conn, ciphertextWithTag); err != nil {
		bufferPool.Put(c.readBuffer)
		c.readBuffer = nil
		return errors.New("failed to read payload").Base(err)
	}

	nonce := c.readNonce[:]
	aad := lengthBytes[:]
	decryptedPlaintext, err := c.readAEAD.Open(c.readBuffer[:0], nonce, ciphertextWithTag, aad)
	if err != nil {
		bufferPool.Put(c.readBuffer)
		c.readBuffer = nil
		return errors.New("AEAD decryption failed").Base(err)
	}

	payloadLen = binary.BigEndian.Uint16(decryptedPlaintext[:2])
	c.readNonce = incrementNonce(c.readNonce)
	c.decryptedData = decryptedPlaintext[2 : 2+payloadLen]
	return nil
}

func (c *QLSConn) Write(b []byte) (int, error) {
	if !c.handshakeDone {
		return 0, errors.New("handshake not done")
	}

	totalSent := 0
	for len(b) > 0 {
		chunkSize := min(len(b), maxPayloadPerRecord-c.writeAEAD.Overhead()-4)
		chunk := b[:chunkSize]

		paddingLen := 0
		if chunkSize < 2048 && c.writeCount < 10 {
			paddingLen = 2048 - chunkSize
			var t [2]byte
			_, err := rand.Read(t[:])
			if err != nil {
				return totalSent, err
			}
			paddingLen += int(binary.BigEndian.Uint16(t[:]) % 1024)
		}

		sealedLen := 2 + chunkSize + c.writeAEAD.Overhead() + paddingLen
		if sealedLen+2 > maxPayloadPerRecord {
			return totalSent, errors.New("payload too large for a single record")
		}

		packetLen := 2 + sealedLen
		writeBuffer := bufferPool.Get(packetLen)

		binary.BigEndian.PutUint16(writeBuffer[0:2], uint16(sealedLen))
		binary.BigEndian.PutUint16(writeBuffer[2:4], uint16(chunkSize))
		copy(writeBuffer[4:4+chunkSize], chunk)

		aad := writeBuffer[0:2]
		nonce := c.writeNonce[:]

		packet := c.writeAEAD.Seal(writeBuffer[:2], nonce, writeBuffer[2:4+chunkSize+paddingLen], aad)

		if _, err := c.Conn.Write(packet); err != nil {
			bufferPool.Put(writeBuffer)
			return totalSent, errors.New("failed to write packet").Base(err)
		}
		bufferPool.Put(writeBuffer)

		if c.writeCount < 10 {
			c.writeCount++
		}

		c.writeNonce = incrementNonce(c.writeNonce)
		totalSent += chunkSize
		b = b[chunkSize:]
	}
	return totalSent, nil
}

func (c *QLSConn) Close() error {
	if c.readBuffer != nil {
		bufferPool.Put(c.readBuffer)
		c.readBuffer = nil
	}
	return c.Conn.Close()
}

func (c *QLSConn) LocalAddr() net.Addr                { return c.Conn.LocalAddr() }
func (c *QLSConn) RemoteAddr() net.Addr               { return c.Conn.RemoteAddr() }
func (c *QLSConn) SetDeadline(t time.Time) error      { return c.Conn.SetDeadline(t) }
func (c *QLSConn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(t) }
func (c *QLSConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }

func (c *QLSConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	if !c.handshakeDone {
		return errors.New("handshake not done")
	}
	for _, b := range mb {
		if b.IsEmpty() {
			continue
		}
		if _, err := c.Write(b.Bytes()); err != nil {
			return err
		}
	}
	return nil
}
