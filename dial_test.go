package probednet_test

import (
	"bytes"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/errors"
	"github.com/getlantern/probednet"
	"github.com/getlantern/probednet/pktutil"
)

// TODO: fix tests; the utilty in testing/main.go works on Windows, but these tests do not

func TestTypes(t *testing.T) {
	var (
		tcpConn *probednet.TCPConn
		udpConn *probednet.UDPConn
	)

	assert.Implements(t, (*net.Conn)(nil), tcpConn)
	assert.Implements(t, (*net.Conn)(nil), udpConn)
	assert.Implements(t, (*probednet.Conn)(nil), tcpConn)
	assert.Implements(t, (*probednet.Conn)(nil), udpConn)
	assert.Implements(t, (*net.PacketConn)(nil), udpConn)
}

func TestDialTCP(t *testing.T) {
	t.Parallel()

	doTests := func(t *testing.T, network string, localhost0 net.TCPAddr) {
		t.Run("nil address", func(t *testing.T) {
			t.Parallel()
			pkts, remote := testDialAndCapture(t, network, func(addr net.Addr) (probednet.Conn, error) {
				return probednet.DialTCP(network, nil, addr.(*net.TCPAddr))
			})
			checkACKs(t, pkts, remote)
		})
		t.Run("wildcard port", func(t *testing.T) {
			t.Parallel()
			pkts, remote := testDialAndCapture(t, network, func(addr net.Addr) (probednet.Conn, error) {
				return probednet.DialTCP(network, &localhost0, addr.(*net.TCPAddr))
			})
			checkACKs(t, pkts, remote)
		})
		t.Run("set port", func(t *testing.T) {
			t.Parallel()
			pkts, remote := testDialAndCapture(t, network, func(addr net.Addr) (probednet.Conn, error) {
				l, err := net.ListenTCP(network, &localhost0)
				require.NoError(t, err)
				require.NoError(t, l.Close())
				return probednet.DialTCP(network, l.Addr().(*net.TCPAddr), addr.(*net.TCPAddr))
			})
			checkACKs(t, pkts, remote)
		})
	}

	t.Run("ipv4", func(t *testing.T) {
		t.Parallel()
		doTests(t, "tcp4", net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	})
	t.Run("ipv6", func(t *testing.T) {
		t.Parallel()
		doTests(t, "tcp6", net.TCPAddr{IP: net.ParseIP("::1")})
	})
	t.Run("generic ip", func(t *testing.T) {
		t.Parallel()
		pkts, remote := testDialAndCapture(t, "tcp", func(addr net.Addr) (probednet.Conn, error) {
			return probednet.DialTCP("tcp", nil, addr.(*net.TCPAddr))
		})
		checkACKs(t, pkts, remote)
	})
}

func TestDialUDP(t *testing.T) {
	t.Parallel()

	doTests := func(t *testing.T, network string, localhost0 net.UDPAddr) {
		t.Run("nil address", func(t *testing.T) {
			t.Parallel()
			testDialAndCapture(t, network, func(addr net.Addr) (probednet.Conn, error) {
				return probednet.DialUDP(network, nil, addr.(*net.UDPAddr))
			})
		})
		t.Run("wildcard port", func(t *testing.T) {
			t.Parallel()
			testDialAndCapture(t, network, func(addr net.Addr) (probednet.Conn, error) {
				return probednet.DialUDP(network, &localhost0, addr.(*net.UDPAddr))
			})
		})
		t.Run("set port", func(t *testing.T) {
			t.Parallel()
			testDialAndCapture(t, network, func(addr net.Addr) (probednet.Conn, error) {
				listenConn, err := net.ListenUDP(network, &localhost0)
				require.NoError(t, err)
				listenConn.Close()
				return probednet.DialUDP(network, listenConn.LocalAddr().(*net.UDPAddr), addr.(*net.UDPAddr))
			})
		})
	}

	t.Run("ipv4", func(t *testing.T) {
		t.Parallel()
		doTests(t, "udp4", net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	})
	t.Run("ipv6", func(t *testing.T) {
		t.Parallel()
		doTests(t, "udp6", net.UDPAddr{IP: net.ParseIP("::1")})
	})
	t.Run("generic ip", func(t *testing.T) {
		t.Parallel()
		testDialAndCapture(t, "udp", func(addr net.Addr) (probednet.Conn, error) {
			return probednet.DialUDP("udp", nil, addr.(*net.UDPAddr))
		})
	})
}

type dialFunc func(net.Addr) (probednet.Conn, error)

func testDialAndCapture(t *testing.T, network string, dial dialFunc) (_ []pktutil.TransportPacket, remote net.Addr) {
	t.Helper()

	const (
		timeout              = time.Second
		clientMsg, serverMsg = "hello from the client", "hello from the server"
	)

	localhost0 := "127.0.0.1:0"
	if network == "tcp6" || network == "udp6" {
		localhost0 = "[::1]:0"
	}

	s, err := newTestServer(network, localhost0)
	require.NoError(t, err)
	defer s.Close()

	done := make(chan struct{})
	defer close(done)

	serverErrors := make(chan error)
	go func() {
		for err := range serverErrors {
			select {
			case <-done:
				return
			default:
				t.Fatal(err)
			}
		}
	}()
	go s.serve([]byte(serverMsg), serverErrors)

	conn, err := dial(s.Addr())
	require.NoError(t, err)

	packets := [][]byte{}
	captureComplete := make(chan struct{})
	go func() {
		for pkt := range conn.CapturedPackets() {
			packets = append(packets, pkt.Data)
		}
		close(captureComplete)
	}()
	go func() {
		for err := range conn.CaptureErrors() {
			t.Fatal(err)
		}
	}()

	require.NoError(t, conn.SetWriteDeadline(time.Now().Add(timeout)))
	_, err = conn.Write([]byte(clientMsg))
	require.NoError(t, err)

	select {
	case receivedClientMsg := <-s.clientMsgsChan():
		assert.Equal(t, []byte(clientMsg), receivedClientMsg)
	case <-time.After(timeout):
		t.Fatal("timed out waiting for client message")
	}

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(timeout)))
	b := make([]byte, 1024)
	n, err := conn.Read(b)
	require.NoError(t, err)
	assert.Equal(t, []byte(serverMsg), b[:n])

	// Wait for remaining packets to come through, then check whether we saw the expected packets.
	conn.Close()
	<-captureComplete

	decodedPackets := []pktutil.TransportPacket{}
	sawClientMsg, sawServerMsg := false, false
	for _, raw := range packets {
		pkt, err := pktutil.DecodeTransportPacket(raw, loopbackLayerType())
		require.NoError(t, err)
		if assert.True(t, pkt.PartOf(conn), "received stray packet") {
			decodedPackets = append(decodedPackets, *pkt)
			if pkt.DestinedFor(conn.RemoteAddr()) {
				sawClientMsg = sawClientMsg || bytes.Equal(pkt.Payload, []byte(clientMsg))
			} else {
				sawServerMsg = sawServerMsg || bytes.Equal(pkt.Payload, []byte(serverMsg))
			}
		}
	}
	assert.True(t, sawClientMsg)
	assert.True(t, sawServerMsg)

	return decodedPackets, s.Addr()
}

// Assumes all packets are TCP packets and part of the same connection.
func checkACKs(t *testing.T, packets []pktutil.TransportPacket, remote net.Addr) {
	t.Helper()

	inboundACKs, outboundACKs := uint32Set{}, uint32Set{}
	for _, pkt := range packets {
		if pkt.DestinedFor(remote) {
			outboundACKs.add(pkt.TCPLayer.Ack)
		} else {
			inboundACKs.add(pkt.TCPLayer.Ack)
		}
	}

	for _, pkt := range packets {
		if pkt.DestinedFor(remote) {
			assert.True(
				t, inboundACKs.contains(pkt.ExpectedACK()),
				"expected to see ACK %d from server; actually seen: %v", pkt.ExpectedACK(), inboundACKs.keys())
		} else {
			assert.True(
				t, outboundACKs.contains(pkt.ExpectedACK()),
				"expected to see ACK %d from client; actually seen: %v", pkt.ExpectedACK(), outboundACKs.keys())
		}
	}
}

type testServer interface {
	serve(responseMsg []byte, errors chan<- error)
	clientMsgsChan() <-chan []byte
	Addr() net.Addr
	Close() error
}

func newTestServer(network, address string) (testServer, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return newTestTCPServer(network, address)
	case "udp", "udp4", "udp6":
		return newTestUDPServer(network, address)
	default:
		return nil, errors.New("unsupported network")
	}
}

type testTCPServer struct {
	net.Listener
	maxReceiveMsgSize int
	clientMsgs        chan []byte
}

func newTestTCPServer(network, address string) (*testTCPServer, error) {
	const defaultMaxReceiveMsgSize = 1024

	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}

	return &testTCPServer{
		Listener:          l,
		maxReceiveMsgSize: defaultMaxReceiveMsgSize,
		clientMsgs:        make(chan []byte),
	}, nil
}

func (s testTCPServer) handleConn(conn net.Conn, responseMsg []byte, errChan chan<- error) {
	for {
		msg := make([]byte, s.maxReceiveMsgSize)
		n, err := conn.Read(msg)
		if err != nil {
			if err == io.EOF {
				return
			}
			if netErr, ok := err.(net.Error); ok && !netErr.Temporary() {
				continue
			}
			errChan <- errors.New("read failed: %v", err)
		}
		s.clientMsgs <- msg[:n]
		if _, err := conn.Write(responseMsg); err != nil {
			errChan <- errors.New("write failed: %v", err)
		}
	}
}

func (s testTCPServer) serve(responseMsg []byte, errChan chan<- error) {
	for {
		conn, err := s.Accept()
		if err != nil {
			// This is an unexported error indicating that the listener is closing.
			// See https://golang.org/pkg/internal/poll/#pkg-variables
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}

			errChan <- errors.New("accept failed: %v", err)
			netErr, ok := err.(net.Error)
			if ok && netErr.Temporary() {
				continue
			}
			return
		}
		go s.handleConn(conn, responseMsg, errChan)
	}
}

func (s testTCPServer) clientMsgsChan() <-chan []byte {
	return s.clientMsgs
}

type testUDPServer struct {
	*net.UDPConn
	maxReceiveMsgSize int
	clientMsgs        chan []byte
}

func newTestUDPServer(network, address string) (*testUDPServer, error) {
	const defaultMaxReceiveMsgSize = 1024

	udpAddr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, errors.New("failed to resolve address: %v", err)
	}
	conn, err := net.ListenUDP(network, udpAddr)
	if err != nil {
		return nil, err
	}
	return &testUDPServer{conn, defaultMaxReceiveMsgSize, make(chan []byte)}, nil
}

func (s testUDPServer) serve(responseMsg []byte, errChan chan<- error) {
	for {
		msg := make([]byte, s.maxReceiveMsgSize)
		n, addr, err := s.ReadFrom(msg)
		if err != nil {
			if err == io.EOF {
				return
			}
			if netErr, ok := err.(net.Error); ok && !netErr.Temporary() {
				continue
			}
			errChan <- errors.New("read failed: %v", err)
		}
		s.clientMsgs <- msg[:n]
		if _, err := s.WriteTo(responseMsg, addr); err != nil {
			errChan <- errors.New("write failed: %v", err)
		}
	}
}

func (s testUDPServer) clientMsgsChan() <-chan []byte {
	return s.clientMsgs
}

func (s testUDPServer) Addr() net.Addr {
	return s.LocalAddr()
}

func loopbackLayerType() gopacket.LayerType {
	switch runtime.GOOS {
	case "linux":
		return layers.LayerTypeEthernet
	default:
		return layers.LayerTypeLoopback
	}
}

type uint32Set map[uint32]bool

func (s uint32Set) add(i uint32)           { s[i] = true }
func (s uint32Set) contains(i uint32) bool { return s[i] }

func (s uint32Set) keys() []uint32 {
	l := []uint32{}
	for k := range s {
		l = append(l, k)
	}
	return l
}
