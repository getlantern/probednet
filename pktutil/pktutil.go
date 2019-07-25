// Package pktutil provides utilities for decoding network packets.
package pktutil

import (
	"bytes"
	"fmt"
	"net"
	"text/tabwriter"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/getlantern/errors"
)

// TransportPacket is a decoded packet at the transport layer.
type TransportPacket struct {
	IPv4Layer *layers.IPv4
	IPv6Layer *layers.IPv6
	TCPLayer  *layers.TCP
	UDPLayer  *layers.UDP
	Payload   gopacket.Payload

	// Timestamp is available for convenience. It will not be set for decoded packets, but users of
	// the TransportPacket type can attach their own timestamps as needed.
	Timestamp time.Time
}

// DecodeTransportPacket decodes a transport packet. The timestamp field will not be set on the
// returned packet.
//
// The firstLayer parameter tells the decoder how to interpret the packet. If this packet is a
// captured packet from a utility in the probednet package, it is likely a link-layer packet. Thus
// firstLayer should be either layers.LayerTypeEthernet or layers.LayerTypeLoopback.
//
// Note that on Linux, loopback packets are encoded in ethernet frames, so even if the packet was
// sent through the loopback interface, you would need to specify firstLayer as
// layers.LayerTypeEthernet.
func DecodeTransportPacket(pkt []byte, firstLayer gopacket.LayerType) (*TransportPacket, error) {
	decoded := gopacket.NewPacket(pkt, firstLayer, gopacket.Lazy)
	tp := TransportPacket{}

	if decoded.NetworkLayer() != nil {
		switch networkLayer := decoded.NetworkLayer().(type) {
		case *layers.IPv4:
			tp.IPv4Layer = networkLayer
		case *layers.IPv6:
			tp.IPv6Layer = networkLayer
		default:
			return nil, errors.New("unexpected network layer type %v", networkLayer.LayerType())
		}
	}

	if decoded.TransportLayer() == nil {
		if decoded.ErrorLayer() != nil {
			return nil, decoded.ErrorLayer().Error()
		}
		return nil, errors.New("no transport layer found")
	}

	switch transportlayer := decoded.TransportLayer().(type) {
	case *layers.TCP:
		tp.TCPLayer = transportlayer
	case *layers.UDP:
		tp.UDPLayer = transportlayer
	default:
		return nil, errors.New("unexpected transport layer type %v", transportlayer.LayerType())
	}
	tp.Payload = decoded.TransportLayer().LayerPayload()

	return &tp, nil
}

// SrcIP provides the packet's source IP address. Returns nil if no IP layer has been decoded.
func (p TransportPacket) SrcIP() net.IP {
	if p.IPv4Layer != nil {
		return p.IPv4Layer.SrcIP
	}
	if p.IPv6Layer != nil {
		return p.IPv6Layer.SrcIP
	}
	return nil
}

// DstIP provides the packet's destination IP address. Returns nil if no IP layer has been decoded.
func (p TransportPacket) DstIP() net.IP {
	if p.IPv4Layer != nil {
		return p.IPv4Layer.DstIP
	}
	if p.IPv6Layer != nil {
		return p.IPv6Layer.DstIP
	}
	return nil
}

// ExpectedACK for this packet. Returns 0 if this is not a TCP packet.
func (p TransportPacket) ExpectedACK() uint32 {
	if p.TCPLayer == nil {
		return 0
	}
	if p.TCPLayer.SYN {
		return p.TCPLayer.Seq + 1
	}
	return p.TCPLayer.Seq + uint32(len(p.Payload))
}

// PartOf returns true iff this is a packet routed between conn.LocalAddr() and conn.RemoteAddr().
func (p TransportPacket) PartOf(conn net.Conn) bool {
	switch conn.LocalAddr().(type) {
	case *net.TCPAddr:
		return p.partOfTCP(conn.LocalAddr().(*net.TCPAddr), conn.RemoteAddr().(*net.TCPAddr))
	case *net.UDPAddr:
		return p.partOfUDP(conn.LocalAddr().(*net.UDPAddr), conn.RemoteAddr().(*net.UDPAddr))
	default:
		panic("unexpected connection type")
	}
}

func (p TransportPacket) partOfTCP(laddr, raddr *net.TCPAddr) bool {
	if p.TCPLayer == nil {
		return false
	}

	correctSrcAndDst := func(src, dst *net.TCPAddr) bool {
		return bytes.Equal(p.SrcIP(), src.IP) &&
			bytes.Equal(p.DstIP(), dst.IP) &&
			int(p.TCPLayer.SrcPort) == src.Port &&
			int(p.TCPLayer.DstPort) == dst.Port
	}
	return correctSrcAndDst(laddr, raddr) || correctSrcAndDst(raddr, laddr)
}

func (p TransportPacket) partOfUDP(laddr, raddr *net.UDPAddr) bool {
	if p.UDPLayer == nil {
		return false
	}

	correctSrcAndDst := func(src, dst *net.UDPAddr) bool {
		return bytes.Equal(p.SrcIP(), src.IP) &&
			bytes.Equal(p.DstIP(), dst.IP) &&
			int(p.UDPLayer.SrcPort) == src.Port &&
			int(p.UDPLayer.DstPort) == dst.Port
	}
	return correctSrcAndDst(laddr, raddr) || correctSrcAndDst(raddr, laddr)
}

// DestinedFor returns true if this packet is destined for addr.
func (p TransportPacket) DestinedFor(addr net.Addr) bool {
	switch addr := addr.(type) {
	case *net.TCPAddr:
		if p.TCPLayer == nil {
			return false
		}
		return bytes.Equal(p.DstIP(), addr.IP) && int(p.TCPLayer.DstPort) == addr.Port
	case *net.UDPAddr:
		if p.UDPLayer == nil {
			return false
		}
		return bytes.Equal(p.DstIP(), addr.IP) && int(p.UDPLayer.DstPort) == addr.Port
	default:
		panic("unrecognized address type")
	}
}

// TCPFlag is a flag on a TCP packet.
type TCPFlag string

// All TCP flags.
const (
	SYN TCPFlag = "SYN"
	FIN TCPFlag = "FIN"
	ACK TCPFlag = "ACK"
	URG TCPFlag = "URG"
	PSH TCPFlag = "PSH"
	RST TCPFlag = "RST"
	ECE TCPFlag = "ECE"
	CWR TCPFlag = "CWR"
	NS  TCPFlag = "NS"
)

var tcpFlags = []TCPFlag{SYN, FIN, ACK, URG, PSH, RST, ECE, CWR, NS}

// Flags returns the set of TCP flags on this packet. The order of the flags in the slice will be
// consistent across packets.
func (p TransportPacket) Flags() []TCPFlag {
	flags := []TCPFlag{}
	for _, f := range tcpFlags {
		if p.HasAllFlags(f) {
			flags = append(flags, f)
		}
	}
	return flags
}

// HasAnyFlags reports whether the packet has any of the input flags.
func (p TransportPacket) HasAnyFlags(flags ...TCPFlag) bool {
	if p.TCPLayer == nil {
		return false
	}

	for _, f := range flags {
		switch {
		case f == SYN && p.TCPLayer.SYN:
			return true
		case f == FIN && p.TCPLayer.FIN:
			return true
		case f == ACK && p.TCPLayer.ACK:
			return true
		case f == URG && p.TCPLayer.URG:
			return true
		case f == PSH && p.TCPLayer.PSH:
			return true
		case f == RST && p.TCPLayer.RST:
			return true
		case f == ECE && p.TCPLayer.ECE:
			return true
		case f == CWR && p.TCPLayer.CWR:
			return true
		case f == NS && p.TCPLayer.NS:
			return true
		}
	}
	return false
}

// HasAllFlags reports whether the packet has all of the input flags.
func (p TransportPacket) HasAllFlags(flags ...TCPFlag) bool {
	if p.TCPLayer == nil {
		return false
	}

	for _, f := range flags {
		switch f {
		case SYN, FIN, ACK, URG, PSH, RST, ECE, CWR, NS:
		default:
			return false
		}

		switch {
		case f == SYN && !p.TCPLayer.SYN:
			return false
		case f == FIN && !p.TCPLayer.FIN:
			return false
		case f == ACK && !p.TCPLayer.ACK:
			return false
		case f == URG && !p.TCPLayer.URG:
			return false
		case f == PSH && !p.TCPLayer.PSH:
			return false
		case f == RST && !p.TCPLayer.RST:
			return false
		case f == ECE && !p.TCPLayer.ECE:
			return false
		case f == CWR && !p.TCPLayer.CWR:
			return false
		case f == NS && !p.TCPLayer.NS:
			return false
		}
	}
	return true
}

// Pprint (pretty print) formats the packet nicely for logging and debugging. If a layer is missing,
// it will not appear in the output.
func (p TransportPacket) Pprint() string {
	buf := new(bytes.Buffer)
	tw := tabwriter.NewWriter(buf, 18, 8, 0, '\t', 0)

	var srcIP, dstIP string
	if sIP := p.SrcIP(); sIP != nil {
		srcIP = sIP.String()
	} else {
		srcIP = "unknown IP"
	}
	if dIP := p.DstIP(); dIP != nil {
		dstIP = dIP.String()
	} else {
		dstIP = "unknown IP"
	}

	var ipProto string
	if p.IPv4Layer != nil {
		ipProto = "IPv4"
	} else if p.IPv6Layer != nil {
		ipProto = "IPv6"
	}

	fmt.Fprintf(tw, "protocol:\t")
	if p.TCPLayer != nil {
		fmt.Fprintf(tw, "TCP")
		if ipProto != "" {
			fmt.Fprintf(tw, "/%s", ipProto)
		}
	} else if p.UDPLayer != nil {
		fmt.Fprintf(tw, "UDP")
		if ipProto != "" {
			fmt.Fprintf(tw, "/%s", ipProto)
		}
	} else if ipProto != "" {
		fmt.Fprint(tw, ipProto)
	} else {
		fmt.Fprint(tw, "unknown")
	}
	fmt.Fprintln(tw)

	fmt.Fprintf(tw, "flow:\t")
	if p.TCPLayer != nil {
		fmt.Fprintf(tw, "[%s]:%d -> [%s]:%d", srcIP, p.TCPLayer.SrcPort, dstIP, p.TCPLayer.DstPort)
	} else if p.UDPLayer != nil {
		fmt.Fprintf(tw, "[%s]:%d -> [%s]:%d", srcIP, p.UDPLayer.SrcPort, dstIP, p.UDPLayer.DstPort)
	} else {
		fmt.Fprintf(tw, "[%s] -> [%s]", srcIP, dstIP)
	}
	fmt.Fprintln(tw)

	if p.TCPLayer != nil {
		fmt.Fprint(tw, "flags:\t")
		for _, flag := range p.Flags() {
			fmt.Fprint(tw, flag, " ")
		}
		fmt.Fprintln(tw)

		fmt.Fprintf(tw, "sequence:\t%d\n", p.TCPLayer.Seq)
		fmt.Fprintf(tw, "acknowledgement:\t%d\n", p.TCPLayer.Ack)
	}

	if len(p.Payload) > 0 {
		fmt.Fprintf(tw, "payload:\t%v\n", p.Payload)
	}

	if !p.Timestamp.IsZero() {
		fmt.Fprintf(tw, "timestamp:\t%v\n", p.Timestamp)
	}

	tw.Flush()
	return buf.String()
}
