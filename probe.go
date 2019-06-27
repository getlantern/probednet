// Package probe offers utilities for actively probing proxies. The general idea is to probe Lantern
// proxies as a censor would, looking for anything which might identify the server as a
// circumvention tool.
package probe

import (
	"net"

	"github.com/getlantern/errors"
)

// Probes on a network connection.
type Probes struct {
	// In receives all inbound packets and Out receives all outbound packets.
	In, Out func(pkt []byte)
}

// Dial behaves like net.Dial, but attaches probes to the connection. These probes receieve input
// and output packets at the layer specified by network. For example, Dial("tcp", addr) will result
// in the probes receiving TCP packets.
//
// Currently supported networks are "tcp4" and "tcp6".
func Dial(network, address string, probes Probes) (net.Conn, error) {
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

	// TODO: use pcap to add probes to connection

	closeConn = false
	return conn, nil
}
