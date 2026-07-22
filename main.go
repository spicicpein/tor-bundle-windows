// tor-bundle-windows: single-binary Windows Tor bundle.
//
// Embeds the Tor core in-process (via go-libtor, cgo) - no subprocess for
// Tor itself. Exposes a local SOCKS5 proxy and a persistent Hidden Service
// that forwards to a local address you configure. Optionally uses obfs4/
// webtunnel (lyrebird) bridges if the network blocks Tor directly - the
// transport binary is embedded in this exe and only extracted to disk if
// bridges are actually configured.
//
// All working files (Tor's data directory, the onion service key, the
// config file, and extracted transport binaries if needed) live in a
// "tor-data" folder right next to this executable - nothing is written to
// AppData, Temp, or any other hidden location.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
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

//go:embed embedded/lyrebird.exe
var lyrebirdBin []byte

type bridgeLine = string

type config struct {
	// Local address that incoming onion connections get forwarded to.
	// Example: "127.0.0.1:22" for SSH, "127.0.0.1:8080" for a web panel.
	ForwardTo string `json:"forward_to"`
	// Virtual port the .onion address listens on (what people connect to).
	OnionPort int `json:"onion_port"`
	// Bridge lines to use if the network blocks Tor directly. Leave empty
	// to try a direct connection only. Get bridge lines from Tor Browser's
	// built-in bridge menu, https://bridges.torproject.org, or the
	// @GetBridgesBot Telegram bot, then paste them here (one per line/entry)
	// and restart. Supports obfs4/webtunnel (lyrebird) bridge lines.
	Bridges []bridgeLine `json:"bridges"`
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
	c := &config{ForwardTo: "127.0.0.1:22", OnionPort: 22, Bridges: []bridgeLine{}}
	b, _ = json.MarshalIndent(c, "", "  ")
	if err := os.WriteFile(path, b, 0644); err != nil {
		return nil, err
	}
	log.Printf("wrote default config to %s - edit it (forward_to, onion_port, bridges) and restart if needed", path)
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

// extractTransports writes the embedded lyrebird binary to binDir (only
// called when bridges are actually configured) and returns its path.
func extractTransports(binDir string) (lyrebirdPath string, err error) {
	if err = os.MkdirAll(binDir, 0700); err != nil {
		return "", err
	}
	lyrebirdPath = filepath.Join(binDir, "lyrebird.exe")
	if err = os.WriteFile(lyrebirdPath, lyrebirdBin, 0755); err != nil {
		return "", err
	}
	return lyrebirdPath, nil
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

	startConf := &tor.StartConf{
		ProcessCreator:    libtor.Creator,
		DataDir:           filepath.Join(base, "state"),
		RetainTempDataDir: true,
	}

	usingBridges := len(cfg.Bridges) > 0
	if usingBridges {
		log.Printf("config has %d bridge line(s) configured - starting with bridges from the start", len(cfg.Bridges))
		lyrebirdPath, err := extractTransports(filepath.Join(base, "bin"))
		if err != nil {
			log.Fatalf("extracting transport binaries: %v", err)
		}
		args := []string{
			"--ClientTransportPlugin", "obfs4,webtunnel exec " + lyrebirdPath,
			"--UseBridges", "1",
		}
		for _, b := range cfg.Bridges {
			args = append(args, "--Bridge", b)
		}
		startConf.ExtraArgs = args
	} else {
		log.Println("no bridges configured - trying a direct connection first")
	}

	log.Println("starting embedded Tor core (first run can take a while)...")
	t, err := tor.Start(nil, startConf)
	if err != nil {
		log.Fatalf("failed to start tor: %v", err)
	}
	defer t.Close()

	timeout := 5 * time.Minute
	if !usingBridges {
		timeout = 90 * time.Second
	}
	bootCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dialer, err := t.Dialer(bootCtx, nil)
	if err == nil {
		if conn, derr := dialer.DialContext(bootCtx, "tcp", "check.torproject.org:80"); derr == nil {
			conn.Close()
			err = nil
		} else {
			err = derr
		}
	}
	if err != nil {
		if usingBridges {
			log.Fatalf("could not bootstrap even with the configured bridges: %v", err)
		}
		log.Println("could not connect directly - the network may be blocking Tor.")
		log.Println("To use bridges: open tor-data/config.json, get bridge lines from")
		log.Println("Tor Browser's built-in bridge menu, https://bridges.torproject.org,")
		log.Println("or the @GetBridgesBot Telegram bot, paste them into \"bridges\", and")
		log.Println("restart this program.")
		log.Fatalf("bootstrap failed: %v", err)
	}
	log.Println("Tor bootstrapped, network reachable.")

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
