package probednet

import (
	"fmt"
	"net"
	"testing"

	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/require"
)

func TestInterfaces(t *testing.T) {
	fmt.Println("net.GetInterfaces():")
	netIfaces, err := net.Interfaces()
	require.NoError(t, err)
	for _, iface := range netIfaces {
		fmt.Printf("\t%+v\n", iface)
		addrs, err := iface.Addrs()
		require.NoError(t, err)
		fmt.Printf("\t\taddresses:%v\n", addrs)
		mcAddrs, err := iface.MulticastAddrs()
		require.NoError(t, err)
		fmt.Printf("\t\tmulticast addresses:%v\n", mcAddrs)
	}

	fmt.Println("\npcap.FindAllDevs():")
	pcapIfaces, err := pcap.FindAllDevs()
	require.NoError(t, err)
	for _, iface := range pcapIfaces {
		fmt.Printf("\t%+v\n", iface)
	}
}
