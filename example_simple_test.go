package probednet_test

import (
	"fmt"

	"github.com/getlantern/probednet"
)

func Example() {
	// Dial can be used just as it would with the standard library's net package.
	conn, err := probednet.Dial("tcp4", "golang.org:80")
	if err != nil {
		panic(fmt.Sprintf("dial failed: %v", err))
	}

	// All packets transmitted as part of the connection can be read out of the connection's
	// CapturedPackets channel.
	done := make(chan struct{})
	go func() {
		for pkt := range conn.CapturedPackets() {
			fmt.Println("captured packet:")
			fmt.Println(pkt.Data)
			fmt.Println()
		}
		close(done)
	}()
	go func() {
		for err := range conn.CaptureErrors() {
			fmt.Println("capture error:", err)
		}
	}()

	// We can use the connection like a regular net.Conn.
	_, err = conn.Write([]byte("hello golang!"))
	if err != nil {
		panic(fmt.Sprintf("failed to write: %v", err))
	}
	conn.Close()

	// After closing the connection, we can wait for the remaining packets to come through by
	// waiting for the CapturedPackets channel to close.
	<-done
}
