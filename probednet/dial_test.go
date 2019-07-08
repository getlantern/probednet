package probednet

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/errors"
)

type testServer struct {
	net.Listener
	maxReceiveMsgSize int
	clientMsgs        chan []byte
}

func newTestServer(network, address string) (*testServer, error) {
	const defaultMaxReceiveMsgSize = 1024

	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}

	return &testServer{
		Listener:          l,
		maxReceiveMsgSize: defaultMaxReceiveMsgSize,
		clientMsgs:        make(chan []byte),
	}, nil
}

func (s testServer) handleConn(conn net.Conn, responseMsg []byte, errChan chan<- error) {
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

func (s testServer) serve(responseMsg []byte, errChan chan<- error) {
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

type tcpPacket struct {
	ipLayer struct {
		SrcIP net.IP
		DstIP net.IP
	}
	tcpLayer layers.TCP
	payload  gopacket.Payload
}

// Decodes a link-layer packet encapsulating a TCP/IP packet. Assumes the packet came over the
// loopback interface.
func decodeTCP(linkPacket []byte) (*tcpPacket, error) {
	var (
		ip4        layers.IPv4
		ip6        layers.IPv6
		decoded    tcpPacket
		layerTypes = []gopacket.LayerType{}
	)
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeLoopback,
		&layers.Loopback{},
		&ip4,
		&ip6,
		&decoded.tcpLayer,
		&decoded.payload,
	)
	if err := parser.DecodeLayers(linkPacket, &layerTypes); err != nil {
		return nil, err
	}
	for _, layerType := range layerTypes {
		switch layerType {
		case layers.LayerTypeIPv4:
			decoded.ipLayer.SrcIP, decoded.ipLayer.DstIP = ip4.SrcIP, ip4.DstIP
		case layers.LayerTypeIPv6:
			decoded.ipLayer.SrcIP, decoded.ipLayer.DstIP = ip6.SrcIP, ip6.DstIP
		}
	}
	return &decoded, nil
}

func (p tcpPacket) expectedACK() uint32 {
	if p.tcpLayer.SYN {
		return p.tcpLayer.Seq + 1
	}
	return p.tcpLayer.Seq + uint32(len(p.payload))
}

// True iff this is a packet routed between conn.LocalAddr() and conn.RemoteAddr().
func (p tcpPacket) partOf(conn *net.TCPConn) bool {
	correctSrcAndDst := func(src, dst *net.TCPAddr) bool {
		return bytes.Equal(p.ipLayer.SrcIP, src.IP) &&
			bytes.Equal(p.ipLayer.DstIP, dst.IP) &&
			int(p.tcpLayer.SrcPort) == src.Port &&
			int(p.tcpLayer.DstPort) == dst.Port
	}
	laddr, raddr := conn.LocalAddr().(*net.TCPAddr), conn.RemoteAddr().(*net.TCPAddr)
	return correctSrcAndDst(laddr, raddr) || correctSrcAndDst(raddr, laddr)
}

func (p tcpPacket) destinedFor(addr net.Addr) bool {
	tcpAddr := addr.(*net.TCPAddr)
	return bytes.Equal(p.ipLayer.DstIP, tcpAddr.IP) && int(p.tcpLayer.DstPort) == tcpAddr.Port
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

func TestDialTCP(t *testing.T) {
	t.Parallel()

	doTests := func(t *testing.T, network string, localhost0 net.TCPAddr) {
		t.Run("nil address", func(t *testing.T) {
			t.Parallel()
			testDialTCPHelper(t, network, func() *net.TCPAddr { return nil })
		})
		t.Run("wildcard port", func(t *testing.T) {
			t.Parallel()
			testDialTCPHelper(t, network, func() *net.TCPAddr { return &localhost0 })
		})
		t.Run("set port", func(t *testing.T) {
			t.Parallel()
			testDialTCPHelper(t, network, func() *net.TCPAddr {
				l, err := net.ListenTCP(network, &localhost0)
				require.NoError(t, err)
				defer l.Close()
				return l.Addr().(*net.TCPAddr)
			})
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
		testDialTCPHelper(t, "tcp", func() *net.TCPAddr { return nil })
	})
}

func testDialTCPHelper(t *testing.T, network string, laddrFunc func() *net.TCPAddr) {
	t.Helper()

	const (
		timeout              = time.Second
		clientMsg, serverMsg = "hello from the client", "hello from the server"
	)

	done := make(chan struct{})
	defer close(done)

	s, err := newTestServer(network, "localhost:0")
	require.NoError(t, err)
	defer s.Close()

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

	conn, err := DialTCP(network, laddrFunc(), s.Addr().(*net.TCPAddr))
	require.NoError(t, err)
	defer conn.Close()

	packets := [][]byte{}
	go func() {
		for pkt := range conn.CapturedPackets() {
			packets = append(packets, pkt.Data)
		}
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
	case receivedClientMsg := <-s.clientMsgs:
		assert.Equal(t, []byte(clientMsg), receivedClientMsg)
	case <-time.After(timeout):
		t.Fatal("timed out waiting for client message")
	}

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(timeout)))
	b := make([]byte, 1024)
	n, err := conn.Read(b)
	require.NoError(t, err)
	assert.Equal(t, []byte(serverMsg), b[:n])

	// Wait for remaining packets to come through, then check whether we saw the packets we expected
	// to on the probes.
	time.Sleep(time.Second)
	conn.CaptureComplete()

	var (
		decodedPackets            = []tcpPacket{}
		inboundACKs, outboundACKs = uint32Set{}, uint32Set{}
	)
	for _, pkt := range packets {
		decoded, err := decodeTCP(pkt)
		require.NoError(t, err)
		if assert.True(t, decoded.partOf(conn.TCPConn), "received stray packet") {
			decodedPackets = append(decodedPackets, *decoded)
			if decoded.destinedFor(conn.RemoteAddr()) {
				outboundACKs.add(decoded.tcpLayer.Ack)
			} else {
				inboundACKs.add(decoded.tcpLayer.Ack)
			}
		}
	}

	sawClientMsg, sawServerMsg := false, false
	for _, pkt := range decodedPackets {
		if pkt.destinedFor(conn.RemoteAddr()) {
			sawClientMsg = sawClientMsg || bytes.Equal(pkt.payload, []byte(clientMsg))
			assert.True(
				t, inboundACKs.contains(pkt.expectedACK()),
				"expected to see ACK %d from server; actually seen: %v", pkt.expectedACK(), inboundACKs.keys())
		} else {
			sawServerMsg = sawServerMsg || bytes.Equal(pkt.payload, []byte(serverMsg))
			assert.True(
				t, outboundACKs.contains(pkt.expectedACK()),
				"expected to see ACK %d from client; actually seen: %v", pkt.expectedACK(), outboundACKs.keys())
		}
	}
	assert.True(t, sawClientMsg)
	assert.True(t, sawServerMsg)
}
