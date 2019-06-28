// Package probe offers utilities for actively probing proxies. The general idea is to probe Lantern
// proxies as a censor would, looking for anything which might identify the server as a
// circumvention tool.
package probe

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
)

// Probes on a network connection.
type Probes struct {
	// In receives all inbound packets and Out receives all outbound packets.
	In, Out func(pkt []byte)

	done     chan struct{}
	initDone sync.Once
}

func (p *Probes) doneChannel() chan struct{} {
	p.initDone.Do(func() { p.done = make(chan struct{}) })
	return p.done
}

// Close the probes.
func (p *Probes) Close() error {
	doneChan := p.doneChannel()
	select {
	case _, ok := <-doneChan:
		if ok {
			close(doneChan)
		}
	default:
		close(doneChan)
	}
	return nil
}

// Dial behaves like net.Dial, but attaches probes to the connection. These probes receieve input
// and output packets at the layer specified by network. For example, Dial("tcp", addr) will result
// in the probes receiving TCP packets.
//
// Currently supported networks are "tcp4" and "tcp6".
func Dial(network, address string, probes *Probes) (net.Conn, error) {
	// TODO: capture beginning of connection (e.g. SYN, SYN/ACK, etc.)

	switch network {
	case "tcp4", "tcp6":
	default:
		return nil, errors.New("unsupported network")
	}

	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	closeConn := true
	defer func() {
		if closeConn {
			conn.Close()
		}
	}()

	var (
		lIP           net.IP
		bpfIn, bpfOut string
	)
	switch network {
	case "tcp4", "tcp6":
		lAddrTCP, err := net.ResolveTCPAddr(network, conn.LocalAddr().String())
		if err != nil {
			return nil, errors.New("failed to obtain local IP for connection: %v", err)
		}
		lIP = lAddrTCP.IP
		bpfIn = fmt.Sprintf("ip dst %v and tcp dst port %d", lAddrTCP.IP, lAddrTCP.Port)
		bpfOut = fmt.Sprintf("ip src %v and tcp src port %d", lAddrTCP.IP, lAddrTCP.Port)
	default:
		return nil, errors.New("unsupported network")
	}

	iface, err := getInterface(lIP)
	if err != nil {
		return nil, errors.New("failed to obtain interface for connection's local address: %v", err)
	}

	handleIn, err := pcap.OpenLive(iface.Name, int32(iface.MTU), false, packetReadTimeout)
	if err != nil {
		return nil, errors.New("failed to open pcap handle: %v", err)
	}
	if err := handleIn.SetBPFFilter(bpfIn); err != nil {
		return nil, errors.New("failed to configure capture filter: %v", err)
	}
	handleOut, err := pcap.OpenLive(iface.Name, int32(iface.MTU), false, packetReadTimeout)
	if err != nil {
		return nil, errors.New("failed to open pcap handle: %v", err)
	}
	if err := handleOut.SetBPFFilter(bpfOut); err != nil {
		return nil, errors.New("failed to configure capture filter: %v", err)
	}

	go readPackets(handleIn, probes.In, probes.doneChannel())
	go readPackets(handleOut, probes.Out, probes.doneChannel())

	closeConn = false
	return conn, nil
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

func readPackets(handle *pcap.Handle, f func([]byte), done chan struct{}) {
	for {
		select {
		case <-done:
			return
		default:
			rawPkt, _, err := handle.ReadPacketData()
			if err != nil {
				// TODO: handle errors
				// debugging
				fmt.Println("failed to read packet data:", err)
				continue
			}
			f(rawPkt)
		}
	}
}
