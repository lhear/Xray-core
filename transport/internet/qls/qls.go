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
	"hash"
	"io"
	"net"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/crypto/hkdf"
)

const (
	maxPayloadPerRecord = 16384 + 256 // 16KB + generous overhead
	// Constants for HKDF labels, following TLS 1.3 conventions
	labelClientHandshakeTraffic = "c hs traffic"
	labelServerHandshakeTraffic = "s hs traffic"
	labelClientAppTraffic       = "c ap traffic"
	labelServerAppTraffic       = "s ap traffic"
	labelExporter               = "exp master"
	labelFinished               = "finished"
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
			// Consider adding conn.RemoteAddr() to the log for easier debugging.
			errors.LogWarning(context.Background(), qlsErr)
			continue
		}

		return qlsConn, nil
	}
}

// handshakeState holds the state for the QLS handshake process.
type handshakeState struct {
	conn         net.Conn
	config       *Config
	transcript   hash.Hash
	localPrivKey *ecdh.PrivateKey
	remotePubKey []byte
}

func newHandshakeState(conn net.Conn, config *Config) *handshakeState {
	return &handshakeState{
		conn:       conn,
		config:     config,
		transcript: sha256.New(),
	}
}

func (hs *handshakeState) generateLocalKeys() error {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return errors.New("failed to generate ecdh key pair").Base(err)
	}
	hs.localPrivKey = privKey
	return nil
}

func (hs *handshakeState) sendClientHello() error {
	clientRandom := make([]byte, 32)
	if _, err := rand.Read(clientRandom); err != nil {
		return errors.New("failed to generate client random").Base(err)
	}

	// Encode the random part to make the initial packet less random-looking
	encodedRandom := make([]byte, ascii85.MaxEncodedLen(len(clientRandom)))
	encodedLen := ascii85.Encode(encodedRandom, clientRandom)
	encodedRandom = encodedRandom[:encodedLen] // Should be 40 bytes

	clientPubKey := hs.localPrivKey.PublicKey().Bytes()
	clientHello := append(encodedRandom, clientPubKey...) // 40 + 32 = 72 bytes

	hs.transcript.Write(clientHello)
	if _, err := hs.conn.Write(clientHello); err != nil {
		return errors.New("failed to send ClientHello").Base(err)
	}
	return nil
}

func (hs *handshakeState) readClientHello() error {
	clientHello := make([]byte, 72) // 40 bytes encoded random + 32 bytes pubkey
	if _, err := io.ReadFull(hs.conn, clientHello); err != nil {
		return errors.New("failed to read ClientHello").Base(err)
	}
	hs.transcript.Write(clientHello)

	// Decode the random part (not used directly, but essential for the transcript)
	encodedRandom := clientHello[:40]
	clientRandom := make([]byte, 32)
	if _, _, err := ascii85.Decode(clientRandom, encodedRandom, true); err != nil {
		return errors.New("failed to decode client random").Base(err)
	}

	hs.remotePubKey = clientHello[40:]
	return nil
}

func (hs *handshakeState) sendServerHello() error {
	serverRandom := make([]byte, 32)
	if _, err := rand.Read(serverRandom); err != nil {
		return errors.New("failed to generate server random").Base(err)
	}
	serverPubKey := hs.localPrivKey.PublicKey().Bytes()
	serverHello := append(serverRandom, serverPubKey...)

	hs.transcript.Write(serverHello)
	if _, err := hs.conn.Write(serverHello); err != nil {
		return errors.New("failed to send ServerHello").Base(err)
	}
	return nil
}

func (hs *handshakeState) readServerHello() error {
	serverHello := make([]byte, 64)
	if _, err := io.ReadFull(hs.conn, serverHello); err != nil {
		return errors.New("failed to read ServerHello").Base(err)
	}
	hs.transcript.Write(serverHello)
	hs.remotePubKey = serverHello[32:]
	return nil
}

func (hs *handshakeState) calculateSharedSecret() ([]byte, error) {
	remoteECDHPubKey, err := ecdh.X25519().NewPublicKey(hs.remotePubKey)
	if err != nil {
		return nil, errors.New("invalid remote public key").Base(err)
	}
	sharedSecret, err := hs.localPrivKey.ECDH(remoteECDHPubKey)
	if err != nil {
		return nil, errors.New("ECDH key exchange failed").Base(err)
	}
	return sharedSecret, nil
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
	serverNonce := [12]byte{} // Nonce for handshake is always 0
	signature, err := serverHandshakeAEAD.Open(nil, serverNonce[:], encryptedSignature, handshakeHash)
	if err != nil {
		return errors.New("failed to decrypt server signature").Base(err)
	}

	if !ed25519.Verify(hs.config.PublicKey, handshakeHash, signature) {
		return errors.New("server signature verification failed")
	}
	return nil
}

func (hs *handshakeState) sendServerSignature(serverHandshakeAEAD cipher.AEAD) error {
	handshakeHash := hs.transcript.Sum(nil)
	serverEd25519PrivKey := ed25519.NewKeyFromSeed(hs.config.PrivateKey)
	signature := ed25519.Sign(serverEd25519PrivKey, handshakeHash)

	serverNonce := [12]byte{} // Nonce for handshake is always 0
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

// Client performs the new, secure QLS handshake.
func Client(ctx context.Context, conn net.Conn, config *Config) (qlsConn stat.Connection, err error) {
	tempConn := &QLSConn{Conn: conn}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	hs := newHandshakeState(conn, config)

	// 1. Generate keys and send ClientHello
	if err = hs.generateLocalKeys(); err != nil {
		return nil, err
	}
	if err = hs.sendClientHello(); err != nil {
		return nil, err
	}

	// 2. Receive ServerHello
	if err = hs.readServerHello(); err != nil {
		return nil, err
	}

	// 3. Derive keys
	sharedSecret, err := hs.calculateSharedSecret()
	if err != nil {
		return nil, err
	}
	handshakeHash := hs.transcript.Sum(nil)
	_, serverHandshakeAEAD, clientAppAEAD, serverAppAEAD, err := deriveKeys(sharedSecret, handshakeHash)
	if err != nil {
		return nil, err
	}

	// 4. Verify server signature
	if err = hs.readAndVerifyServerSignature(serverHandshakeAEAD); err != nil {
		return nil, err
	}

	// Handshake successful
	tempConn.writeAEAD = clientAppAEAD
	tempConn.readAEAD = serverAppAEAD
	tempConn.handshakeDone = true

	errors.LogInfo(ctx, "handshake successful")
	return stat.Connection(tempConn), nil
}

// Server performs the new, secure QLS handshake.
func Server(ctx context.Context, conn net.Conn, config *Config) (qlsConn stat.Connection, err error) {
	tempConn := &QLSConn{Conn: conn}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	// Set a deadline for the entire handshake.
	if config.HandshakeTimeout > 0 {
		conn.SetDeadline(time.Now().Add(time.Duration(config.HandshakeTimeout) * time.Millisecond))
	} else {
		conn.SetDeadline(time.Now().Add(5 * time.Second)) // Default to 5 seconds
	}
	defer conn.SetDeadline(time.Time{})

	hs := newHandshakeState(conn, config)

	// 1. Receive ClientHello
	if err = hs.readClientHello(); err != nil {
		return nil, err
	}

	// 2. Generate keys and send ServerHello
	if err = hs.generateLocalKeys(); err != nil {
		return nil, err
	}
	if err = hs.sendServerHello(); err != nil {
		return nil, err
	}

	// 3. Derive keys
	sharedSecret, err := hs.calculateSharedSecret()
	if err != nil {
		return nil, err
	}
	handshakeHash := hs.transcript.Sum(nil)
	_, serverHandshakeAEAD, clientAppAEAD, serverAppAEAD, err := deriveKeys(sharedSecret, handshakeHash)
	if err != nil {
		return nil, err
	}

	// 4. Send server signature
	if err = hs.sendServerSignature(serverHandshakeAEAD); err != nil {
		return nil, err
	}

	// Handshake successful
	tempConn.readAEAD = clientAppAEAD
	tempConn.writeAEAD = serverAppAEAD
	tempConn.handshakeDone = true

	errors.LogInfo(ctx, "handshake successful")
	return stat.Connection(tempConn), nil
}

// hkdfExpandLabel is a helper function to derive secrets using HKDF-Expand-Label as defined in RFC 8446.
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

// deriveKeys derives handshake and application keys from a shared secret and transcript hash.
func deriveKeys(sharedSecret, transcriptHash []byte) (cipher.AEAD, cipher.AEAD, cipher.AEAD, cipher.AEAD, error) {
	// 1. Handshake Keys
	earlySecret := hkdf.Extract(sha256.New, sharedSecret, []byte(handshakeSalt))
	clientHandshakeSecret := hkdfExpandLabel(earlySecret, labelClientHandshakeTraffic, transcriptHash, 32)
	serverHandshakeSecret := hkdfExpandLabel(earlySecret, labelServerHandshakeTraffic, transcriptHash, 32)

	// 2. Application Keys
	derivedSecret := hkdfExpandLabel(earlySecret, "derived", nil, 32)
	masterSecret := hkdf.Extract(sha256.New, nil, derivedSecret)
	clientAppSecret := hkdfExpandLabel(masterSecret, labelClientAppTraffic, transcriptHash, 32)
	serverAppSecret := hkdfExpandLabel(masterSecret, labelServerAppTraffic, transcriptHash, 32)

	// 3. Create AEAD ciphers
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

// incrementNonce increments a 12-byte nonce by 1.
func incrementNonce(nonce [12]byte) [12]byte {
	counter := binary.BigEndian.Uint64(nonce[4:])
	counter++
	binary.BigEndian.PutUint64(nonce[4:], counter)
	if counter == 0 { // overflow
		binary.BigEndian.PutUint32(nonce[0:4], binary.BigEndian.Uint32(nonce[0:4])+1)
	}
	return nonce
}

// Read from the QLS connection.
func (c *QLSConn) Read(b []byte) (int, error) {
	if !c.handshakeDone {
		return 0, errors.New("handshake not done")
	}

	// If there's leftover data from the previous read, use it first.
	if len(c.decryptedData) > 0 {
		n := copy(b, c.decryptedData)
		c.decryptedData = c.decryptedData[n:]
		if len(c.decryptedData) == 0 {
			bufferPool.Put(c.readBuffer)
			c.readBuffer = nil
		}
		return n, nil
	}

	// No leftover data, so we need to read and decrypt a new record.
	if err := c.readRecord(); err != nil {
		return 0, err
	}

	// Now that a new record is in decryptedData, copy it to the user's buffer.
	n := copy(b, c.decryptedData)
	c.decryptedData = c.decryptedData[n:]

	if len(c.decryptedData) == 0 {
		bufferPool.Put(c.readBuffer)
		c.readBuffer = nil
	}

	return n, nil
}

// readRecord reads a single encrypted record from the underlying connection,
// decrypts it, and stores the plaintext in c.decryptedData.
func (c *QLSConn) readRecord() error {
	if c.readBuffer != nil {
		bufferPool.Put(c.readBuffer)
		c.readBuffer = nil
	}

	var lengthBytes [2]byte
	if _, err := io.ReadFull(c.Conn, lengthBytes[:]); err != nil {
		return err // Propagate EOF and other errors
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
	// Use the received length as AAD
	aad := lengthBytes[:]
	decryptedPlaintext, err := c.readAEAD.Open(c.readBuffer[:0], nonce, ciphertextWithTag, aad)
	if err != nil {
		bufferPool.Put(c.readBuffer)
		c.readBuffer = nil
		return errors.New("AEAD decryption failed").Base(err)
	}

	c.readNonce = incrementNonce(c.readNonce)
	c.decryptedData = decryptedPlaintext
	return nil
}

// Write to the QLS connection.
func (c *QLSConn) Write(b []byte) (int, error) {
	if !c.handshakeDone {
		return 0, errors.New("handshake not done")
	}

	totalSent := 0
	for len(b) > 0 {
		chunkSize := len(b)
		if chunkSize > maxPayloadPerRecord {
			chunkSize = maxPayloadPerRecord
		}
		chunk := b[:chunkSize]

		sealedLen := len(chunk) + c.writeAEAD.Overhead()
		if sealedLen > 65535 {
			// This should not happen if maxPayloadPerRecord is set correctly.
			return totalSent, errors.New("payload too large for a single record")
		}

		// Get a buffer for the entire packet: [2-byte length][sealed_payload]
		packetLen := 2 + sealedLen
		writeBuffer := bufferPool.Get(packetLen)

		// Write length into the first 2 bytes
		binary.BigEndian.PutUint16(writeBuffer[0:2], uint16(sealedLen))

		// Use the length as AAD
		aad := writeBuffer[0:2]
		nonce := c.writeNonce[:]

		// Seal the payload, appending it to the buffer right after the length.
		packet := c.writeAEAD.Seal(writeBuffer[:2], nonce, chunk, aad)

		// Write the entire packet (length + sealed payload)
		if _, err := c.Conn.Write(packet); err != nil {
			bufferPool.Put(writeBuffer)
			return totalSent, errors.New("failed to write packet").Base(err)
		}
		bufferPool.Put(writeBuffer)

		c.writeNonce = incrementNonce(c.writeNonce)
		totalSent += len(chunk)
		b = b[chunkSize:]
	}
	return totalSent, nil
}

// Close the QLS connection.
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
