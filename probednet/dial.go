// Package probednet offers utilities for probing constructions of the net package.
package probednet

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"

	"github.com/getlantern/errors"
)

const (
	// Warning: do not set to >= 1 second: https://github.com/google/gopacket/issues/499
	packetReadTimeout = 500 * time.Millisecond

	channelBufferSize = 1000
)

// Packet represents a network packet.
type Packet struct {
	Data []byte

	// Timestamp is the time the packet was captured, if that is known.
	Timestamp time.Time
}

// Conn is a network connection with probes capturing packets on the connection.
type Conn interface {
	net.Conn

	// CapturedPackets can be used to read packets trasmitted as part of the connection. Packets on
	// this channel will be link-layer packets. The specific type depends on the network interface
	// used for the connection. Usually, these will be ethernet frames. For connections through the
	// loopback interface, these will be loopback packets and the exact structure depends on your
	// operating system.
	//
	// This channel will be closed when the connection is closed or CaptureComplete is called.
	CapturedPackets() <-chan Packet

	// CaptureErrors holds errors associated with packet capture. Errors on this channel do not
	// necessarily indicate errors on the connection.
	//
	// This channel will be closed when the connection is closed or CaptureComplete is called.
	CaptureErrors() <-chan error

	// CaptureComplete can be used to stop packet capture. The connection itself is unaffected.
	CaptureComplete()
}

// TCPConn - like net.TCPConn - is an implementation of the Conn interface for TCP network
// connections.
type TCPConn struct {
	*net.TCPConn
	*handleReader
}

// Close the connection.
func (c *TCPConn) Close() error {
	// Note: handleReader.Close() has no return value.
	c.handleReader.Close()
	return c.TCPConn.Close()
}

type handleReader struct {
	handle          *pcap.Handle
	capturedPackets chan Packet
	captureErrors   chan error
	done            bool
	doneLock        *sync.RWMutex
}

func newHandleReader(handle *pcap.Handle) *handleReader {
	hr := handleReader{
		handle,
		make(chan Packet, channelBufferSize),
		make(chan error, channelBufferSize),
		false,
		new(sync.RWMutex),
	}
	go func() {
		for done := hr.readPacket(); !done; done = hr.readPacket() {
		}
	}()
	return &hr
}

// The handle reader methods reference the instance as "c" because they appear in docs as methods on
// connection types like TCPConn.

func (c *handleReader) readPacket() (done bool) {
	c.doneLock.RLock()
	defer c.doneLock.RUnlock()

	if c.done {
		return true
	}

	pkt, captureInfo, err := c.handle.ReadPacketData()
	if err != nil {
		if nextErr, ok := err.(pcap.NextError); ok && nextErr == pcap.NextErrorTimeoutExpired {
			return false
		}
		select {
		case c.captureErrors <- err:
		default:
		}
		return false
	}
	select {
	case c.capturedPackets <- Packet{pkt, captureInfo.Timestamp}:
	default:
	}
	return false
}

func (c *handleReader) CapturedPackets() <-chan Packet {
	return c.capturedPackets
}

func (c *handleReader) CaptureErrors() <-chan error {
	return c.captureErrors
}

func (c *handleReader) Close() {
	c.doneLock.Lock()
	defer c.doneLock.Unlock()
	if c.done {
		return
	}

	// Note: pcap.Handle.Close has no return value.
	c.handle.Close()
	close(c.capturedPackets)
	close(c.captureErrors)
	c.done = true
}

func (c *handleReader) CaptureComplete() {
	c.Close()
}

// Dial behaves like net.Dial, but attaches a probe to the connection.
//
// Currently supported networks are "tcp", "tcp4", and "tcp6".
func Dial(network, address string) (Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		raddr, err := net.ResolveTCPAddr(network, address)
		if err != nil {
			return nil, errors.New("failed to resolve address: %v", err)
		}
		return DialTCP(network, nil, raddr)
	default:
		return nil, errors.New("unsupported network")
	}
}

// DialTCP behaves like net.DialTCP, but attaches a probe to the connection.
func DialTCP(network string, laddr, raddr *net.TCPAddr) (*TCPConn, error) {
	// TODO: test IPv6

	deferred := new(deferStack)
	defer deferred.call()

	laddr, freeLaddr, err := chooseLaddr(network, laddr, raddr)
	if err != nil {
		return nil, errors.New("failed to set local address: %v", err)
	}
	deferred.push(func() { freeLaddr() })

	bpf := fmt.Sprintf(
		"(%s) or (%s)",
		fmt.Sprintf("ip dst %v and tcp dst port %d", laddr.IP, laddr.Port),
		fmt.Sprintf("ip src %v and tcp src port %d", laddr.IP, laddr.Port),
	)

	iface, err := getInterface(laddr.IP)
	if err != nil {
		return nil, errors.New("failed to obtain interface for connection's local address: %v", err)
	}

	handle, err := pcap.OpenLive(iface.Name, int32(iface.MTU), false, packetReadTimeout)
	if err != nil {
		return nil, errors.New("failed to open pcap handle: %v", err)
	}
	deferred.push(handle.Close)
	if err := handle.SetBPFFilter(bpf); err != nil {
		return nil, errors.New("failed to configure capture filter: %v", err)
	}

	hr := newHandleReader(handle)
	deferred.push(hr.Close)
	if err := freeLaddr(); err != nil {
		return nil, errors.New("unable to free local address for use: %v", err)
	}
	netConn, err := net.DialTCP(network, laddr, raddr)
	if err != nil {
		return nil, err
	}
	deferred.cancel()
	return &TCPConn{netConn, hr}, nil
}

// Chooses a local address based on the network and remote address. Any fields set on the input
// local address will be honored. Returns the selected local address and a function to free the
// port. The free function should be called immediately before using the address.
func chooseLaddr(network string, laddr, raddr *net.TCPAddr) (*net.TCPAddr, func() error, error) {
	if laddr == nil {
		outboundIP, err := preferredOutboundIP(raddr.IP)
		if err != nil {
			return nil, nil, errors.New("no route to remote: %v", err)
		}
		laddr = &net.TCPAddr{IP: outboundIP}
	}
	if laddr.Port == 0 {
		l, err := net.ListenTCP(network, laddr)
		if err != nil {
			return nil, nil, errors.New("failed to find free port: %v", err)
		}
		return l.Addr().(*net.TCPAddr), l.Close, nil
	}
	return laddr, func() error { return nil }, nil
}

func preferredOutboundIP(remoteIP net.IP) (net.IP, error) {
	// Note: the choice of port below does not actually matter. It just needs to be non-zero.
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: remoteIP, Port: 999})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP, nil
}

func getInterface(ip net.IP) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, errors.New("failed to obtain system interfaces: %v", err)
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, errors.New("failed to obtain addresses for %s: %v", iface.Name, err)
		}
		for _, addr := range addrs {
			ipNet, err := parseNetwork(addr.String())
			if err != nil {
				return nil, errors.New("failed to parse interface address %s as IP network: %v", addr.String(), err)
			}
			if ipNet.Contains(ip) {
				return &iface, nil
			}
		}
	}
	return nil, errors.New("no network interface for %v", ip)
}

// Parses a network of addresses like 127.0.0.1/8. Inputs like 127.0.0.1 are valid and will be
// interpreted as equivalent to 127.0.0.1/0.
func parseNetwork(addr string) (*net.IPNet, error) {
	splits := strings.Split(addr, "/")

	var (
		ip       net.IP
		maskOnes int
		err      error
	)
	switch len(splits) {
	case 1:
		ip = net.ParseIP(addr)
		maskOnes = 0
	case 2:
		ip = net.ParseIP(splits[0])
		maskOnes, err = strconv.Atoi(splits[1])
		if err != nil {
			return nil, errors.New("expected integer after '/' character, found %s", splits[1])
		}
	default:
		return nil, errors.New("expected one or zero '/' characters in address, found %d", len(splits))
	}

	if ip == nil {
		return nil, errors.New("failed to parse network number as IP address")
	}
	var mask net.IPMask
	if ip.To4() != nil {
		mask = net.CIDRMask(maskOnes, 32)
	} else {
		mask = net.CIDRMask(maskOnes, 128)
	}
	return &net.IPNet{IP: ip, Mask: mask}, nil
}
