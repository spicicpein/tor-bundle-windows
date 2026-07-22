// tor-bundle-windows: single-binary Tor SOCKS5 client (embedded core, no subprocess for Tor itself).
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/cretz/bine/tor"
	"github.com/gen2brain/go-libtor"
)

func main() {
	log.Println("starting embedded Tor core (this can take up to a couple minutes)...")

	t, err := tor.Start(nil, &tor.StartConf{
		ProcessCreator:         libtor.Creator,
		TempDataDirBase:        "tor-data",
		RetainTempDataDir:      true,
		NoAutoSocksPort:        false,
	})
	if err != nil {
		log.Fatalf("failed to start tor: %v", err)
	}
	defer t.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dialer, err := t.Dialer(ctx, nil)
	if err != nil {
		log.Fatalf("failed to create dialer: %v", err)
	}

	fmt.Println("bootstrapped. testing a request over the embedded Tor SOCKS5 dialer...")
	conn, err := dialer.DialContext(ctx, "tcp", "check.torproject.org:80")
	if err != nil {
		log.Fatalf("test dial failed: %v", err)
	}
	conn.Close()
	fmt.Println("SUCCESS: embedded Tor core is working, connection established over the network.")
}
