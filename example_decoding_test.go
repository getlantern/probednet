package probednet_test

import (
	"bytes"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/getlantern/probednet"
)

var tcpFlags = []struct {
	name    string
	present func(layers.TCP) bool
}{
	{"SYN", func(p layers.TCP) bool { return p.SYN }},
	{"FIN", func(p layers.TCP) bool { return p.FIN }},
	{"ACK", func(p layers.TCP) bool { return p.ACK }},
	{"URG", func(p layers.TCP) bool { return p.URG }},
	{"PSH", func(p layers.TCP) bool { return p.PSH }},
	{"RST", func(p layers.TCP) bool { return p.RST }},
	{"ECE", func(p layers.TCP) bool { return p.ECE }},
	{"CWR", func(p layers.TCP) bool { return p.CWR }},
	{"NS", func(p layers.TCP) bool { return p.NS }},
}

// Note that captured packets will be link-layer packets. If we were connecting to a host on the
// loopback interface, we would need to use loopback decoders instead of ethernet decoders below.
func sprintTCP(linkPacket []byte) string {
	var (
		ip4        layers.IPv4
		ip6        layers.IPv6
		tcp        layers.TCP
		payload    gopacket.Payload
		layerTypes = []gopacket.LayerType{}
	)
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&layers.Ethernet{},
		&ip4,
		&ip6,
		&tcp,
		&payload,
	)
	if err := parser.DecodeLayers(linkPacket, &layerTypes); err != nil {
		return fmt.Sprintf("failed to decode packet: %v", err)
	}

	var srcIP, dstIP net.IP
	for _, layerType := range layerTypes {
		switch layerType {
		case layers.LayerTypeIPv4:
			srcIP, dstIP = ip4.SrcIP, ip4.DstIP
		case layers.LayerTypeIPv6:
			srcIP, dstIP = ip6.SrcIP, ip6.DstIP
		}
	}

	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "[%s]:%d -> [%s]:%d\n", srcIP, tcp.SrcPort, dstIP, tcp.DstPort)
	fmt.Fprintf(buf, "seq: %d\n", tcp.Seq)
	fmt.Fprintf(buf, "ack: %d\n", tcp.Ack)
	for _, flag := range tcpFlags {
		if flag.present(tcp) {
			fmt.Fprint(buf, flag.name, " ")
		}
	}
	fmt.Fprintln(buf)
	if len(payload) > 0 {
		fmt.Fprintln(buf, "payload:", payload)
	}
	return buf.String()
}

// ExampleDecodingWithGopacket demonstrates how a consumer of the probednet package might decode
// captured packets. Libraries like github.com/google/gopacket work well for this.
func Example_decodingWithGopacket() {
	conn, err := probednet.Dial("tcp4", "golang.org:80")
	if err != nil {
		panic(fmt.Sprintf("dial failed: %v", err))
	}

	done := make(chan struct{})
	go func() {
		for pkt := range conn.CapturedPackets() {
			fmt.Println(sprintTCP(pkt.Data))
		}
		close(done)
	}()
	go func() {
		for err := range conn.CaptureErrors() {
			fmt.Println("capture error:", err)
		}
	}()

	_, err = conn.Write([]byte("hello golang!"))
	if err != nil {
		panic(fmt.Sprintf("failed to write: %v", err))
	}
	conn.Close()
	<-done

	// Running this will produce output like the following:
	//
	// [172.16.1.237]:53260 -> [172.217.164.113]:80
	// seq: 620108986
	// ack: 0
	// SYN

	// [172.217.164.113]:80 -> [172.16.1.237]:53260
	// seq: 3098406713
	// ack: 620108987
	// SYN ACK

	// [172.16.1.237]:53260 -> [172.217.164.113]:80
	// seq: 620108987
	// ack: 3098406714
	// ACK

	// [172.16.1.237]:53260 -> [172.217.164.113]:80
	// seq: 620108987
	// ack: 3098406714
	// ACK PSH
	// payload: 13 byte(s)

	// [172.16.1.237]:53260 -> [172.217.164.113]:80
	// seq: 620109000
	// ack: 3098406714
	// FIN ACK

	// [172.217.164.113]:80 -> [172.16.1.237]:53260
	// seq: 3098406714
	// ack: 620109000
	// ACK

	// [172.217.164.113]:80 -> [172.16.1.237]:53260
	// seq: 3098406714
	// ack: 620109001
	// FIN ACK

	// [172.16.1.237]:53260 -> [172.217.164.113]:80
	// seq: 620109001
	// ack: 3098406715
	// ACK
}
