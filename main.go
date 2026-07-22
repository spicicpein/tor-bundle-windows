// tor-bundle-windows: single-binary Windows Tor bundle.
//
// Embeds the Tor core in-process (via go-libtor, cgo) - no subprocess for
// Tor itself. Exposes a local SOCKS5 proxy and a persistent Hidden Service
// that forwards to a local address you configure.
//
// All working files (Tor's data directory, the onion service key, and the
// config file) live in a "tor-data" folder right next to this executable -
// nothing is written to AppData, Temp, or any other hidden location.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cretz/bine/tor"
	"github.com/gen2brain/go-libtor"
)

type config struct {
	// Local address that incoming onion connections get forwarded to.
	// Example: "127.0.0.1:22" for SSH, "127.0.0.1:8080" for a web panel.
	ForwardTo string `json:"forward_to"`
	// Virtual port the .onion address listens on (what people connect to).
	OnionPort int `json:"onion_port"`
}

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(exe))
	if err != nil {
		return filepath.Dir(exe)
	}
	return dir
}

func loadOrCreateConfig(path string) (*config, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		var c config
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		return &c, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	c := &config{ForwardTo: "127.0.0.1:22", OnionPort: 22}
	b, _ = json.MarshalIndent(c, "", "  ")
	if err := os.WriteFile(path, b, 0644); err != nil {
		return nil, err
	}
	log.Printf("wrote default config to %s - edit forward_to/onion_port and restart if needed", path)
	return c, nil
}

func loadOrCreateOnionKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err == nil && len(b) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(b), nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, priv, 0600); err != nil {
		return nil, err
	}
	log.Printf("generated a new onion service key at %s (keep this file to keep the same .onion address)", path)
	return priv, nil
}

func proxyConn(a net.Conn, forwardTo string) {
	defer a.Close()
	b, err := net.DialTimeout("tcp", forwardTo, 15*time.Second)
	if err != nil {
		log.Printf("could not reach forward target %s: %v", forwardTo, err)
		return
	}
	defer b.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}

func main() {
	base := filepath.Join(exeDir(), "tor-data")
	if err := os.MkdirAll(base, 0700); err != nil {
		log.Fatalf("cannot create data folder %s: %v", base, err)
	}

	cfg, err := loadOrCreateConfig(filepath.Join(base, "config.json"))
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	key, err := loadOrCreateOnionKey(filepath.Join(base, "onion.key"))
	if err != nil {
		log.Fatalf("onion key: %v", err)
	}

	log.Println("starting embedded Tor core (first run can take a while)...")
	t, err := tor.Start(nil, &tor.StartConf{
		ProcessCreator:    libtor.Creator,
		DataDir:           filepath.Join(base, "state"),
		RetainTempDataDir: true,
	})
	if err != nil {
		log.Fatalf("failed to start tor: %v", err)
	}
	defer t.Close()

	bootCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	dialer, err := t.Dialer(bootCtx, nil)
	if err != nil {
		log.Fatalf("failed to create dialer: %v", err)
	}
	if conn, err := dialer.DialContext(bootCtx, "tcp", "check.torproject.org:80"); err != nil {
		log.Fatalf("bootstrap check failed: %v", err)
	} else {
		conn.Close()
		log.Println("Tor bootstrapped, network reachable.")
	}

	onion, err := t.Listen(bootCtx, &tor.ListenConf{
		Key:         key,
		Version3:    true,
		RemotePorts: []int{cfg.OnionPort},
	})
	if err != nil {
		log.Fatalf("failed to create hidden service: %v", err)
	}
	defer onion.Close()

	fmt.Println("========================================")
	fmt.Printf("Onion address: %s.onion:%d\n", onion.ID, cfg.OnionPort)
	fmt.Printf("Forwarding to: %s\n", cfg.ForwardTo)
	fmt.Println("========================================")

	for {
		conn, err := onion.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			return
		}
		go proxyConn(conn, cfg.ForwardTo)
	}
}
