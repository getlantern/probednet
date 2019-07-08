package probednet

import (
	"bytes"
	"io"
	"net"
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

type tcp4Packet struct {
	ipLayer  layers.IPv4
	tcpLayer layers.TCP
	payload  gopacket.Payload
}

// Decodes a link-layer packet encapsulating a TCP/IPv4 packet. Assumes the packet came over the
// loopback interface.
func decodeTCP4(linkPacket []byte) (*tcp4Packet, error) {
	decoded := tcp4Packet{}
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeLoopback,
		&layers.Loopback{},
		&decoded.ipLayer,
		&decoded.tcpLayer,
		&decoded.payload,
	)
	if err := parser.DecodeLayers(linkPacket, &[]gopacket.LayerType{}); err != nil {
		return nil, err
	}
	return &decoded, nil
}

func (p tcp4Packet) expectedACK() uint32 {
	if p.tcpLayer.SYN {
		return p.tcpLayer.Seq + 1
	}
	return p.tcpLayer.Seq + uint32(len(p.payload))
}

// True iff this is a packet routed between conn.LocalAddr() and conn.RemoteAddr().
func (p tcp4Packet) partOf(conn *net.TCPConn) bool {
	correctSrcAndDst := func(src, dst *net.TCPAddr) bool {
		return bytes.Equal(p.ipLayer.SrcIP, src.IP) &&
			bytes.Equal(p.ipLayer.DstIP, dst.IP) &&
			int(p.tcpLayer.SrcPort) == src.Port &&
			int(p.tcpLayer.DstPort) == dst.Port
	}
	laddr, raddr := conn.LocalAddr().(*net.TCPAddr), conn.RemoteAddr().(*net.TCPAddr)
	return correctSrcAndDst(laddr, raddr) || correctSrcAndDst(raddr, laddr)
}

func (p tcp4Packet) destinedFor(addr net.Addr) bool {
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

	localhost0 := net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}

	t.Run("nil address", func(t *testing.T) {
		t.Parallel()
		testDialTCPHelper(t, "tcp4", func() *net.TCPAddr { return nil })
	})
	t.Run("wildcard port", func(t *testing.T) {
		t.Parallel()
		testDialTCPHelper(t, "tcp4", func() *net.TCPAddr { return &localhost0 })
	})
	t.Run("set port", func(t *testing.T) {
		t.Parallel()
		testDialTCPHelper(t, "tcp4", func() *net.TCPAddr {
			l, err := net.ListenTCP("tcp4", &localhost0)
			require.NoError(t, err)
			defer l.Close()
			return l.Addr().(*net.TCPAddr)
		})
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
		select {
		case err := <-serverErrors:
			t.Fatal("received error from server:", err)
		case <-done:
			return
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

	// TODO: check conn.CaptureErrors

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
		decodedPackets            = []tcp4Packet{}
		inboundACKs, outboundACKs = uint32Set{}, uint32Set{}
	)
	for _, pkt := range packets {
		decoded, err := decodeTCP4(pkt)
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
