package connectionpolicy_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestNaiveHTTP2KeepsPhysicalPeerAndPadding(t *testing.T) {
	runtime, address := startProxyCore(t, "naive")
	echo, _ := echoServer(t)
	transport := &http2.Transport{AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, _, address string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", address)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = writer.Close(); _ = reader.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	request, err := http.NewRequestWithContext(ctx, http.MethodConnect, "http://"+address, reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("-connect-authority", echo)
	request.Header.Set("Padding", "test")
	request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:test-only")))
	request.Header.Set("X-Forwarded-For", "192.0.2.99")
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	if response.StatusCode != http.StatusOK {
		t.Fatalf("naive CONNECT: %d", response.StatusCode)
	}
	if _, err := writer.Write([]byte{0, 1, 0, 42}); err != nil {
		t.Fatal(err)
	}
	assertPaddingEcho(t, response.Body)
	assertPhysicalReport(t, runtime)
}

func assertPaddingEcho(t *testing.T, reader io.Reader) {
	t.Helper()
	var header [3]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		t.Fatal(err)
	}
	dataSize, paddingSize := int(binary.BigEndian.Uint16(header[:2])), int(header[2])
	data := make([]byte, dataSize+paddingSize)
	if _, err := io.ReadFull(reader, data); err != nil {
		t.Fatal(err)
	}
	if dataSize != 1 || data[0] != 42 {
		t.Fatal("naive padding or payload was changed")
	}
}
