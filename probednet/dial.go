// Package probednet offers utilities for probing constructions of the net package.
package probednet

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
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

// TODO: combine Probes.Inbound and Probes.Outbound

// Probes on a network connection. All channels are buffered and if these buffers fill, data will be
// lost.
type Probes struct {
	// Inbound and Outbound packets. Packets on these channels will be link-layer packets. The
	// specific type depends on the network interface used for the connection. Usually, these will
	// be ethernet frames. For connections through the loopback interface, these will be loopback
	// packets and the exact structure depends on your operating system.
	Inbound, Outbound <-chan Packet

	Errors <-chan error

	DroppedPackets, DroppedErrors int32

	// Same instances of the above channels, but bi-directional.
	inbound, outbound chan Packet
	errors            chan error

	done chan struct{}
}

func startProbes(in, out *pcap.Handle) *Probes {
	p := Probes{
		inbound:  make(chan Packet, channelBufferSize),
		outbound: make(chan Packet, channelBufferSize),
		errors:   make(chan error, channelBufferSize),
		done:     make(chan struct{}),
	}
	p.Inbound, p.Outbound, p.Errors = p.inbound, p.outbound, p.errors
	go p.read(in, p.inbound)
	go p.read(out, p.outbound)
	return &p
}

func (p *Probes) read(handle *pcap.Handle, packets chan<- Packet) {
	for {
		select {
		case <-p.done:
			return
		default:
			pkt, captureInfo, err := handle.ReadPacketData()
			if err != nil {
				select {
				case p.errors <- err:
				default:
					atomic.AddInt32(&p.DroppedErrors, 1)
				}
				continue
			}
			select {
			case packets <- Packet{pkt, captureInfo.Timestamp}:
			default:
				atomic.AddInt32(&p.DroppedPackets, 1)
			}
		}
	}
}

// Close the probes. This can be done before or after closing the associated connection.
func (p *Probes) Close() error {
	close(p.done)
	return nil
}

// Dial behaves like net.Dial, but attaches probes to the connection.
//
// Currently supported networks are "tcp", "tcp4", and "tcp6".
func Dial(network, address string) (net.Conn, *Probes, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		raddr, err := net.ResolveTCPAddr(network, address)
		if err != nil {
			return nil, nil, errors.New("failed to resolve address: %v", err)
		}
		return DialTCP(network, nil, raddr)
	default:
		return nil, nil, errors.New("unsupported network")
	}
}

// DialTCP behaves like net.DialTCP, but attaches probes to the connection.
//
// Currently supported networks are "tcp", "tcp4", and "tcp6".
func DialTCP(network string, laddr, raddr *net.TCPAddr) (*net.TCPConn, *Probes, error) {
	// TODO: test IPv6

	laddr, freeLaddr, err := chooseLaddr(network, laddr, raddr)
	if err != nil {
		return nil, nil, errors.New("failed to set local address: %v", err)
	}

	bpfIn := fmt.Sprintf("ip dst %v and tcp dst port %d", laddr.IP, laddr.Port)
	bpfOut := fmt.Sprintf("ip src %v and tcp src port %d", laddr.IP, laddr.Port)

	iface, err := getInterface(laddr.IP)
	if err != nil {
		return nil, nil, errors.New("failed to obtain interface for connection's local address: %v", err)
	}

	// TODO: handles need to be closed

	handleIn, err := pcap.OpenLive(iface.Name, int32(iface.MTU), false, packetReadTimeout)
	if err != nil {
		return nil, nil, errors.New("failed to open pcap handle: %v", err)
	}
	if err := handleIn.SetBPFFilter(bpfIn); err != nil {
		return nil, nil, errors.New("failed to configure capture filter: %v", err)
	}
	handleOut, err := pcap.OpenLive(iface.Name, int32(iface.MTU), false, packetReadTimeout)
	if err != nil {
		return nil, nil, errors.New("failed to open pcap handle: %v", err)
	}
	if err := handleOut.SetBPFFilter(bpfOut); err != nil {
		return nil, nil, errors.New("failed to configure capture filter: %v", err)
	}

	probes := startProbes(handleIn, handleOut)
	if err := freeLaddr(); err != nil {
		probes.Close()
		return nil, nil, errors.New("unable to free local address for use: %v", err)
	}
	conn, err := net.DialTCP(network, laddr, raddr)
	if err != nil {
		probes.Close()
		return nil, nil, err
	}
	return conn, probes, nil
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
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: remoteIP, Port: 80})
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