package qls_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/qls"
)

func TestQLSHandshake(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i)
	}

	pubKey, _ := mldsa65.NewKeyFromSeed(&seed)

	seedB64 := base64.RawURLEncoding.EncodeToString(seed[:])

	serverConf := &conf.QLSConfig{
		PrivateKey: seedB64,
	}

	clientConf := &conf.QLSConfig{
		PublicKey: base64.RawURLEncoding.EncodeToString(pubKey.Bytes()),
	}

	serverConfig, err := serverConf.Build()
	if err != nil {
		t.Fatalf("Failed to build server config: %v", err)
	}

	clientConfig, err := clientConf.Build()
	if err != nil {
		t.Fatalf("Failed to build client config: %v", err)
	}

	qlsServerConfig, ok := serverConfig.(*qls.Config)
	if !ok {
		t.Fatal("Server config is not of type *qls.Config")
	}

	qlsClientConfig, ok := clientConfig.(*qls.Config)
	if !ok {
		t.Fatal("Client config is not of type *qls.Config")
	}

	if qlsServerConfig.PrivateKey == nil {
		t.Error("Server config should have private key")
	}

	if qlsClientConfig.PublicKey == nil {
		t.Error("Client config should have public key")
	}
}

func TestDataReadWrite(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i)
	}

	pubKey, _ := mldsa65.NewKeyFromSeed(&seed)

	seedB64 := base64.RawURLEncoding.EncodeToString(seed[:])

	serverConf := &conf.QLSConfig{
		PrivateKey: seedB64,
	}

	clientConf := &conf.QLSConfig{
		PublicKey: base64.RawURLEncoding.EncodeToString(pubKey.Bytes()),
	}

	serverConfig, err := serverConf.Build()
	if err != nil {
		t.Fatalf("Failed to build server config: %v", err)
	}

	clientConfig, err := clientConf.Build()
	if err != nil {
		t.Fatalf("Failed to build client config: %v", err)
	}

	qlsServerConfig, ok := serverConfig.(*qls.Config)
	if !ok {
		t.Fatal("Server config is not of type *qls.Config")
	}

	qlsClientConfig, ok := clientConfig.(*qls.Config)
	if !ok {
		t.Fatal("Client config is not of type *qls.Config")
	}

	serverConn, clientConn := net.Pipe()

	handshakeDone := make(chan error, 2)

	var serverQLSConn net.Conn
	go func() {
		conn, err := qls.Server(context.Background(), serverConn, qlsServerConfig)
		serverQLSConn = conn
		handshakeDone <- err
	}()

	var clientQLSConn net.Conn
	go func() {
		conn, err := qls.Client(context.Background(), clientConn, qlsClientConfig)
		clientQLSConn = conn
		handshakeDone <- err
	}()

	timeout := time.After(5 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case err := <-handshakeDone:
			if err != nil {
				t.Fatalf("Handshake failed: %v", err)
			}
		case <-timeout:
			t.Fatal("Handshake timed out")
		}
	}

	testData := []byte("Hello, QLS! This is a test message for data read/write functionality.")

	go func() {
		_, err := clientQLSConn.Write(testData)
		if err != nil {
			t.Errorf("Failed to write data from client: %v", err)
		}
	}()

	buf := make([]byte, len(testData))
	n, err := serverQLSConn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read data on server: %v", err)
	}

	if n != len(testData) {
		t.Errorf("Expected to read %d bytes, got %d", len(testData), n)
	}

	if !bytes.Equal(buf[:n], testData) {
		t.Errorf("Data mismatch. Expected: %s, Got: %s", string(testData), string(buf[:n]))
	}

	responseData := []byte("Hello back from server!")

	go func() {
		_, err := serverQLSConn.Write(responseData)
		if err != nil {
			t.Errorf("Failed to write data from server: %v", err)
		}
	}()

	buf = make([]byte, len(responseData))
	n, err = clientQLSConn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read data on client: %v", err)
	}

	if n != len(responseData) {
		t.Errorf("Expected to read %d bytes, got %d", len(responseData), n)
	}

	if !bytes.Equal(buf[:n], responseData) {
		t.Errorf("Data mismatch. Expected: %s, Got: %s", string(responseData), string(buf[:n]))
	}

	clientQLSConn.Close()
	serverQLSConn.Close()
}

func TestDataReadWriteLarge(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i)
	}

	pubKey, _ := mldsa65.NewKeyFromSeed(&seed)

	seedB64 := base64.RawURLEncoding.EncodeToString(seed[:])

	serverConf := &conf.QLSConfig{
		PrivateKey: seedB64,
	}

	clientConf := &conf.QLSConfig{
		PublicKey: base64.RawURLEncoding.EncodeToString(pubKey.Bytes()),
	}

	serverConfig, err := serverConf.Build()
	if err != nil {
		t.Fatalf("Failed to build server config: %v", err)
	}

	clientConfig, err := clientConf.Build()
	if err != nil {
		t.Fatalf("Failed to build client config: %v", err)
	}

	qlsServerConfig, ok := serverConfig.(*qls.Config)
	if !ok {
		t.Fatal("Server config is not of type *qls.Config")
	}

	qlsClientConfig, ok := clientConfig.(*qls.Config)
	if !ok {
		t.Fatal("Client config is not of type *qls.Config")
	}

	serverConn, clientConn := net.Pipe()

	handshakeDone := make(chan error, 2)

	var serverQLSConn net.Conn
	go func() {
		conn, err := qls.Server(context.Background(), serverConn, qlsServerConfig)
		serverQLSConn = conn
		handshakeDone <- err
	}()

	var clientQLSConn net.Conn
	go func() {
		conn, err := qls.Client(context.Background(), clientConn, qlsClientConfig)
		clientQLSConn = conn
		handshakeDone <- err
	}()

	timeout := time.After(5 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case err := <-handshakeDone:
			if err != nil {
				t.Fatalf("Handshake failed: %v", err)
			}
		case <-timeout:
			t.Fatal("Handshake timed out")
		}
	}

	largeData := make([]byte, 1024*1024)
	_, err = rand.Read(largeData)
	if err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	go func() {
		_, err := clientQLSConn.Write(largeData)
		if err != nil {
			t.Errorf("Failed to write large data from client: %v", err)
		}
	}()

	receivedData := make([]byte, len(largeData))
	totalRead := 0
	for totalRead < len(largeData) {
		n, err := serverQLSConn.Read(receivedData[totalRead:])
		if err != nil {
			t.Fatalf("Failed to read large data on server: %v", err)
		}
		totalRead += n
	}

	if totalRead != len(largeData) {
		t.Errorf("Expected to read %d bytes, got %d", len(largeData), totalRead)
	}

	if !bytes.Equal(receivedData, largeData) {
		t.Error("Large data mismatch")
	}

	responseData := make([]byte, 512*1024)
	_, err = rand.Read(responseData)
	if err != nil {
		t.Fatalf("Failed to generate random response data: %v", err)
	}

	go func() {
		_, err := serverQLSConn.Write(responseData)
		if err != nil {
			t.Errorf("Failed to write large data from server: %v", err)
		}
	}()

	clientReceivedData := make([]byte, len(responseData))
	clientTotalRead := 0
	for clientTotalRead < len(responseData) {
		n, err := clientQLSConn.Read(clientReceivedData[clientTotalRead:])
		if err != nil {
			t.Fatalf("Failed to read large data on client: %v", err)
		}
		clientTotalRead += n
	}

	if clientTotalRead != len(responseData) {
		t.Errorf("Expected to read %d bytes, got %d", len(responseData), clientTotalRead)
	}

	if !bytes.Equal(clientReceivedData, responseData) {
		t.Error("Large response data mismatch")
	}

	clientQLSConn.Close()
	serverQLSConn.Close()
}
