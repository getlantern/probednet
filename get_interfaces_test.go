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
		fmt.Println("\t\taddresses:")
		for _, addr := range addrs {
			fmt.Println("\t\t\t", addr)
			switch addrT := addr.(type) {
			case *net.IPAddr:
				fmt.Println("\t\t\tis loopback:", addrT.IP.IsLoopback())
			case *net.IPNet:
				fmt.Println("\t\t\tis loopback:", addrT.IP.IsLoopback())
			}
		}
		// mcAddrs, err := iface.MulticastAddrs()
		// require.NoError(t, err)
		// fmt.Printf("\t\tmulticast addresses:%v\n", mcAddrs)
	}

	fmt.Println("\npcap.FindAllDevs():")
	pcapIfaces, err := pcap.FindAllDevs()
	require.NoError(t, err)
	for _, iface := range pcapIfaces {
		fmt.Printf("\t%+v\n", iface)
		fmt.Println("\t\taddresses:")
		for _, addr := range iface.Addresses {
			fmt.Println("\t\t\t", addr)
			fmt.Println("\t\t\tis loopback:", addr.IP.IsLoopback())
		}
	}
}
