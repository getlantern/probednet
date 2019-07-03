package probe

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

func TestDial(t *testing.T) {
	t.Parallel()

	const (
		timeout              = time.Second
		clientMsg, serverMsg = "hello from the client", "hello from the server"
	)

	done := make(chan struct{})
	defer close(done)

	s, err := newTestServer("tcp4", "127.0.0.1:0")
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

	conn, probes, err := Dial("tcp4", s.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	inboundPackets, outboundPackets := [][]byte{}, [][]byte{}
	go func() {
		for {
			select {
			case <-done:
				return
			case pkt := <-probes.Inbound:
				inboundPackets = append(inboundPackets, pkt.Data)
			}
		}
	}()
	go func() {
		for {
			select {
			case <-done:
				return
			case pkt := <-probes.Outbound:
				outboundPackets = append(outboundPackets, pkt.Data)
			}
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
	probes.Close()

	var (
		inboundDecoded, outboundDecoded = []tcp4Packet{}, []tcp4Packet{}
		inboundACKs, outboundACKs       = uint32Set{}, uint32Set{}
	)
	for _, pkt := range inboundPackets {
		decoded, err := decodeTCP4(pkt)
		require.NoError(t, err)
		inboundDecoded = append(inboundDecoded, *decoded)
		inboundACKs.add(decoded.tcpLayer.Ack)
	}
	for _, pkt := range outboundPackets {
		decoded, err := decodeTCP4(pkt)
		require.NoError(t, err)
		outboundDecoded = append(outboundDecoded, *decoded)
		outboundACKs.add(decoded.tcpLayer.Ack)
	}

	sawClientMsg, sawServerMsg := false, false
	for _, pkt := range inboundDecoded {
		sawServerMsg = sawServerMsg || bytes.Equal(pkt.payload, []byte(serverMsg))
		expectedACK := pkt.tcpLayer.Seq + uint32(len(pkt.tcpLayer.Payload))
		assert.True(
			t, outboundACKs.contains(expectedACK),
			"expected to see ACK %d from client; actually seen: %v", expectedACK, outboundACKs.keys())
	}
	for _, pkt := range outboundDecoded {
		sawClientMsg = sawClientMsg || bytes.Equal(pkt.payload, []byte(clientMsg))
		expectedACK := pkt.tcpLayer.Seq + uint32(len(pkt.tcpLayer.Payload))
		assert.True(
			t, inboundACKs.contains(expectedACK),
			"expected to see ACK %d from server; actually seen: %v", expectedACK, inboundACKs.keys())
	}
	assert.True(t, sawClientMsg)
	assert.True(t, sawServerMsg)
}
