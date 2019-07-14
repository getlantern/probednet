// Package pktutil provides utilities for decoding network packets.
package pktutil

import (
	"bytes"
	"net"
	"runtime"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TransportPacket is a decoded packet at the transport layer.
type TransportPacket struct {
	IPv4Layer *layers.IPv4
	IPv6Layer *layers.IPv6
	TCPLayer  *layers.TCP
	UDPLayer  *layers.UDP
	Payload   gopacket.Payload
}

// DecodeTransportPacket decodes a transport packet from the link layer.
func DecodeTransportPacket(linkPacket []byte) (*TransportPacket, error) {
	var (
		ip4 layers.IPv4
		ip6 layers.IPv6
		tcp layers.TCP
		udp layers.UDP

		linkLayerType gopacket.LayerType
		linkLayer     gopacket.DecodingLayer

		decoded           = TransportPacket{}
		decodedLayerTypes = []gopacket.LayerType{}
	)

	switch runtime.GOOS {
	case "linux":
		linkLayerType = layers.LayerTypeEthernet
		linkLayer = &layers.Ethernet{}
	default:
		linkLayerType = layers.LayerTypeLoopback
		linkLayer = &layers.Loopback{}
	}

	parser := gopacket.NewDecodingLayerParser(
		linkLayerType,
		linkLayer,
		&ip4,
		&ip6,
		&tcp,
		&udp,
		&decoded.Payload,
	)
	if err := parser.DecodeLayers(linkPacket, &decodedLayerTypes); err != nil {
		return nil, err
	}
	for _, layerType := range decodedLayerTypes {
		switch layerType {
		case layers.LayerTypeIPv4:
			decoded.IPv4Layer = &ip4
		case layers.LayerTypeIPv6:
			decoded.IPv6Layer = &ip6
		case layers.LayerTypeTCP:
			decoded.TCPLayer = &tcp
		case layers.LayerTypeUDP:
			decoded.UDPLayer = &udp
		}
	}
	return &decoded, nil
}

// SrcIP provides the packet's source IP address. Panics if no IP layer has been decoded.
func (p TransportPacket) SrcIP() net.IP {
	if p.IPv4Layer != nil {
		return p.IPv4Layer.SrcIP
	}
	if p.IPv6Layer != nil {
		return p.IPv6Layer.SrcIP
	}
	panic("no IP layer decoded")
}

// DstIP provides the packet's destination IP address. Panics if no IP layer has been decoded.
func (p TransportPacket) DstIP() net.IP {
	if p.IPv4Layer != nil {
		return p.IPv4Layer.DstIP
	}
	if p.IPv6Layer != nil {
		return p.IPv6Layer.DstIP
	}
	panic("no IP layer decoded")
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
