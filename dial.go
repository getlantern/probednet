// Package probednet offers utilities for probing constructions of the net package.
//
// Note that packet capture usually requires elevated permissions and the functions in this package
// are no exception.
//
// This package requires the following system libraries:
// 	Linux:		libpcap-dev
//	Windows: 	npcap or winpcap
//	Mac OS: 	libpcap (installed by default)
package probednet

import (
	"context"
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
	packetReadTimeout = 100 * time.Millisecond

	// We introduce a brief delay before closing the packet capture handle. This is basically time
	// between a call to handleReader.Close and handleReader actually ceasing to read packets and
	// closing the packet channel. From testing different options, this delay seems to work well.
	handleCloseDelay = time.Second

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
	// Note that there is a delay in capturing packets.
	//
	// This channel will be closed when the connection is closed or CaptureComplete is called. When
	// the connection is closed, there will be a short delay before the channel is closed to ensure
	// that the final packets are captured.
	CapturedPackets() <-chan Packet

	// CaptureErrors holds errors associated with packet capture. Errors on this channel do not
	// necessarily indicate errors on the connection.
	//
	// This channel will be closed when the connection is closed or CaptureComplete is called.
	CaptureErrors() <-chan error

	// CaptureComplete can be used to stop packet capture. The connection itself is unaffected.
	CaptureComplete()
}

type genericConn struct {
	net.Conn
	*handleReader
}

// Close the connection
func (c *genericConn) Close() error {
	// Close the handle reader after closing the connection to ensure we capture the final packets.
	defer c.handleReader.Close()
	return c.Conn.Close()
}

// TCPConn - like net.TCPConn - is the implementation of the Conn interface for TCP network
// connections.
type TCPConn struct {
	*net.TCPConn
	*handleReader
}

// Close the connection.
func (c *TCPConn) Close() error {
	// Close the handle reader after closing the connection to ensure we capture the final packets.
	defer c.handleReader.Close()
	return c.TCPConn.Close()
}

// UDPConn - like net.UDPConn - is the implementation of the Conn and net.PacketConn interfaces for
// UDP network connections.
type UDPConn struct {
	*net.UDPConn
	*handleReader
}

// Close the connection.
func (c *UDPConn) Close() error {
	// Close the handle reader after closing the connection to ensure we capture the final packets.
	defer c.handleReader.Close()
	return c.UDPConn.Close()
}

type handleReader struct {
	handle          *pcap.Handle
	capturedPackets chan Packet
	captureErrors   chan error
	done            bool
	doneLock        *sync.RWMutex
}

func newHandleReader(laddr net.Addr) (*handleReader, error) {
	var (
		ip        net.IP
		port      int
		transport string
	)

	switch laddr := laddr.(type) {
	case *net.TCPAddr:
		ip = laddr.IP
		port = laddr.Port
		transport = "tcp"
	case *net.UDPAddr:
		ip = laddr.IP
		port = laddr.Port
		transport = "udp"
	default:
		return nil, errors.New("unsupported address type %T", laddr)
	}

	network := "ip"
	if ip.To4() == nil {
		network = "ip6"
	}

	bpf := fmt.Sprintf(
		"(%s) or (%s)",
		fmt.Sprintf("%s dst %v and %s dst port %d", network, ip, transport, port),
		fmt.Sprintf("%s src %v and %s src port %d", network, ip, transport, port),
	)

	iface, err := getInterface(ip)
	if err != nil {
		return nil, errors.New("failed to obtain interface for connection's local address: %v", err)
	}

	handle, err := pcap.OpenLive(iface.Name, int32(iface.MTU), false, packetReadTimeout)
	if err != nil {
		return nil, errors.New("failed to open pcap handle: %v", err)
	}
	if err := handle.SetBPFFilter(bpf); err != nil {
		handle.Close()
		return nil, errors.New("failed to configure capture filter: %v", err)
	}

	hr := handleReader{
		handle,
		make(chan Packet, channelBufferSize),
		make(chan error, channelBufferSize),
		false,
		new(sync.RWMutex),
	}
	go func() {
		for done := false; !done; done = hr.readPacket() {
		}
	}()
	return &hr, nil
}

// The handleReader methods reference the instance as "c" because they appear in docs as methods on
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
	// Wait a bit before closing the handle to ensure we capture remaining transmitted packets.
	go func() {
		time.Sleep(handleCloseDelay)
		c.CaptureComplete()
	}()
}

func (c *handleReader) CaptureComplete() {
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

// Dial behaves like net.Dial, but attaches a probe to the connection.
//
// Supported networks are "tcp", "tcp4", "tcp6", "udp", "udp4", and "udp6".
func Dial(network, address string) (Conn, error) {
	return DialWith(net.Dialer{}, network, address)
}

// DialTimeout behaves like net.DialTimeout, but attaches a probe to the connection.
//
// Supported networks are "tcp", "tcp4", "tcp6", "udp", "udp4", and "udp6".
func DialTimeout(network, address string, timeout time.Duration) (Conn, error) {
	return DialWith(net.Dialer{Timeout: timeout}, network, address)
}

// DialTCP behaves like net.DialTCP, but attaches a probe to the connection.
func DialTCP(network string, laddr, raddr *net.TCPAddr) (*TCPConn, error) {
	netConn, hr, err := dialWith(net.Dialer{LocalAddr: laddr}, network, raddr.String())
	if err != nil {
		return nil, err
	}
	return &TCPConn{netConn.(*net.TCPConn), hr}, nil
}

// DialUDP behaves like net.DialUDP, but attaches a probe to the connection.
func DialUDP(network string, laddr, raddr *net.UDPAddr) (*UDPConn, error) {
	netConn, hr, err := dialWith(net.Dialer{LocalAddr: laddr}, network, raddr.String())
	if err != nil {
		return nil, err
	}
	return &UDPConn{netConn.(*net.UDPConn), hr}, nil
}

// DialWith behaves like d.Dial, but attaches a probe to the connection.
//
// Supported networks are "tcp", "tcp4", "tcp6", "udp", "udp4", and "udp6".
func DialWith(d net.Dialer, network, address string) (Conn, error) {
	netConn, hr, err := dialWith(d, network, address)
	if err != nil {
		return nil, err
	}
	return &genericConn{netConn, hr}, nil
}

// DialContextWith behaves like d.DialContext, but attaches a probe to the connection.
//
// Supported networks are "tcp", "tcp4", "tcp6", "udp", "udp4", and "udp6".
func DialContextWith(ctx context.Context, d net.Dialer, network, address string) (Conn, error) {
	netConn, hr, err := dialContextWith(ctx, d, network, address)
	if err != nil {
		return nil, err
	}
	return &genericConn{netConn, hr}, nil
}

func dialWith(d net.Dialer, network, address string) (net.Conn, *handleReader, error) {
	return dialContextWith(context.Background(), d, network, address)
}

func dialContextWith(ctx context.Context, d net.Dialer, network, address string) (net.Conn, *handleReader, error) {
	deferred := new(deferStack)
	defer deferred.call()

	var (
		raddr, laddr net.Addr
		freeLaddr    func() error
		err          error
	)
	switch network {
	case "tcp", "tcp4", "tcp6":
		var laddrTCP *net.TCPAddr
		var ok bool
		if d.LocalAddr != nil {
			laddrTCP, ok = d.LocalAddr.(*net.TCPAddr)
			if !ok {
				return nil, nil, errors.New("local address must be a *net.TCPAddr")
			}
		}
		raddr, err = net.ResolveTCPAddr(network, address)
		if err != nil {
			return nil, nil, errors.New("failed to resolve address: %v", err)
		}
		laddr, freeLaddr, err = chooseLaddrTCP(network, laddrTCP, raddr.(*net.TCPAddr))
		if err != nil {
			return nil, nil, errors.New("failed to set local address: %v", err)
		}
		deferred.push(func() { freeLaddr() })

	case "udp", "udp4", "udp6":
		var laddrUDP *net.UDPAddr
		var ok bool
		if d.LocalAddr != nil {
			laddrUDP, ok = d.LocalAddr.(*net.UDPAddr)
			if !ok {
				return nil, nil, errors.New("local address must be a *net.UDPAddr")
			}
		}
		raddr, err = net.ResolveUDPAddr(network, address)
		if err != nil {
			return nil, nil, errors.New("failed to resolve address: %v", err)
		}
		laddr, freeLaddr, err = chooseLaddrUDP(network, laddrUDP, raddr.(*net.UDPAddr))
		if err != nil {
			return nil, nil, errors.New("failed to set local address: %v", err)
		}
		deferred.push(func() { freeLaddr() })

	default:
		return nil, nil, errors.New("unsupported network")
	}

	hr, err := newHandleReader(laddr)
	if err != nil {
		return nil, nil, errors.New("failed to open capture handle: %v", err)
	}
	deferred.push(hr.Close)

	if err := freeLaddr(); err != nil {
		return nil, nil, errors.New("unable to free local address for use: %v", err)
	}
	d.LocalAddr = laddr
	netConn, err := d.DialContext(ctx, network, raddr.String())
	if err != nil {
		return nil, nil, err
	}
	deferred.cancel()
	return netConn, hr, nil
}

// Chooses a local address based on the network and remote address. Any fields set on the input
// local address will be honored. Returns the selected local address and a function to free the
// port. The free function should be called immediately before using the address.
func chooseLaddrTCP(network string, laddr, raddr *net.TCPAddr) (*net.TCPAddr, func() error, error) {
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

// Chooses a local address based on the network and remote address. Any fields set on the input
// local address will be honored. Returns the selected local address and a function to free the
// port. The free function should be called immediately before using the address.
func chooseLaddrUDP(network string, laddr, raddr *net.UDPAddr) (*net.UDPAddr, func() error, error) {
	if laddr == nil {
		outboundIP, err := preferredOutboundIP(raddr.IP)
		if err != nil {
			return nil, nil, errors.New("no route to remote: %v", err)
		}
		laddr = &net.UDPAddr{IP: outboundIP}
	}
	if laddr.Port == 0 {
		conn, err := net.ListenUDP(network, laddr)
		if err != nil {
			return nil, nil, errors.New("failed to find free port: %v", err)
		}
		return conn.LocalAddr().(*net.UDPAddr), conn.Close, nil
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
