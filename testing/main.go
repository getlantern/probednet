package main

import (
	"fmt"
	"log"
	"os"

	"github.com/getlantern/probednet"
	"github.com/getlantern/probednet/pktutil"
	"github.com/google/gopacket/layers"
)

func main() {
	conn, err := probednet.Dial("tcp", os.Args[1])
	if err != nil {
		panic(err)
	}

	done := make(chan struct{})
	go func() {
		for pkt := range conn.CapturedPackets() {
			decoded, err := pktutil.DecodeTransportPacket(pkt.Data, layers.LayerTypeEthernet)
			if err != nil {
				log.Println("failed to decode packet:", err)
			}
			fmt.Println(decoded.Pprint())
		}
		close(done)
	}()
	go func() {
		for err := range conn.CaptureErrors() {
			log.Println("capture error:", err)
		}
	}()

	if _, err := conn.Write([]byte("hello world")); err != nil {
		log.Println("failed to write to connection:", err)
	}
	conn.Close()
	<-done
}
