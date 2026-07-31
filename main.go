// tor-bundle-windows: single-binary Windows Tor bundle.
//
// Embeds the Tor core in-process (via go-libtor, cgo) - no subprocess for
// Tor itself. Exposes a local unified SOCKS5+HTTP(CONNECT) proxy and one or
// more Hidden Service port mappings under a single persistent .onion
// address. Optionally uses obfs4/webtunnel (lyrebird) bridges if the
// network blocks Tor directly.
//
// All working files live in a "slake" folder right next to this
// executable - nothing is written to AppData, Temp, or any hidden location.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cretz/bine/control"
	"github.com/cretz/bine/tor"
	torutilEd25519 "github.com/cretz/bine/torutil/ed25519"
	"github.com/gen2brain/go-libtor"
	"github.com/kardianos/service"
	"github.com/miekg/dns"
)

//go:embed embedded/lyrebird.exe
var lyrebirdBin []byte

type bridgeLine = string

type onionMapping struct {
	OnionPort int    `json:"onion_port"`
	ForwardTo string `json:"forward_to"`
}

type config struct {
	// "127.0.0.1" for local-only access, "0.0.0.0" to allow other devices
	// on the network to use the proxy too.
	ListenAddress string `json:"listen_address"`
	// Single local port serving both SOCKS5 and HTTP(CONNECT) proxy -
	// the protocol is auto-detected per connection.
	ProxyPort int `json:"proxy_port"`
	// One or more onion_port -> forward_to mappings, all under the same
	// .onion address (one persistent key for the whole program).
	OnionServices []onionMapping `json:"onion_services"`
	// Bridge lines to use if the network blocks Tor directly. Leave empty
	// to try a direct connection only. Get bridge lines from Tor Browser's
	// built-in bridge menu, https://bridges.torproject.org, or the
	// @GetBridgesBot Telegram bot, then paste them here and restart.
	Bridges []bridgeLine `json:"bridges"`

	// Optional: a URL of your own choosing (doesn't have to be GitHub, or
	// anything specific) that serves a JSON file like
	// {"updated":"...","bridges":["obfs4 ...", ...]}. If the network seems
	// to be blocking Tor directly and no "bridges" are set above, this URL
	// is fetched (over a plain, non-Tor connection) and used instead. Left
	// empty, this feature is off. No specific address is hardcoded - you
	// choose and control where this points.
	BridgeSource bridgeSourceConfig `json:"bridge_source"`

	DNS dnsConfig `json:"dns"`

	// While running with bridges, periodically checks that Tor can still
	// actually reach the network. If it stops working (bridges "died"),
	// runs an external command/script once - do whatever you want there
	// (email, Telegram bot, Windows notification, etc.) - this program
	// doesn't send notifications itself.
	BridgeHealthCheck bridgeHealthCheckConfig `json:"bridge_health_check"`

	// Deprecated single-service fields, only read to migrate old configs.
	LegacyForwardTo string `json:"forward_to,omitempty"`
	LegacyOnionPort int    `json:"onion_port,omitempty"`
}

type bridgeHealthCheckConfig struct {
	Enabled         bool   `json:"enabled"`
	IntervalMinutes int    `json:"interval_minutes"`
	OnDead          string `json:"on_dead"`
}

type bridgeSourceConfig struct {
	// One or more of your own collector URLs, tried in order until one
	// works. Having more than one means a single blocked/removed address
	// doesn't take the whole feature down.
	URLs []string `json:"urls"`
}

type dnsConfig struct {
	// Turns the embedded DNS server on/off. Off by default.
	Enabled bool `json:"enabled"`
	// If true, names are resolved through Tor (the resolution itself is
	// hidden from your ISP/network). If false, the embedded server still
	// runs but resolves normally, same as your OS would.
	OverTor bool `json:"over_tor"`
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

// migrateOldFolder renames a previous "tor-data" working folder to the new
// name, if present, so an existing onion key (and address) isn't orphaned.
func migrateOldFolder(newBase string) {
	oldBase := filepath.Join(filepath.Dir(newBase), "tor-data")
	if oldBase == newBase {
		return
	}
	if _, err := os.Stat(newBase); err == nil {
		return
	}
	if _, err := os.Stat(oldBase); err != nil {
		return
	}
	if err := os.Rename(oldBase, newBase); err != nil {
		log.Printf("could not rename old tor-data folder to slake: %v", err)
		return
	}
	log.Println("renamed tor-data folder to slake (kept your existing onion key/address)")
}

func loadOrCreateConfig(path string) (*config, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		var c config
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		changed := false
		if len(c.OnionServices) == 0 && c.LegacyForwardTo != "" {
			c.OnionServices = []onionMapping{{OnionPort: c.LegacyOnionPort, ForwardTo: c.LegacyForwardTo}}
			changed = true
		}
		if c.LegacyForwardTo != "" || c.LegacyOnionPort != 0 {
			c.LegacyForwardTo = ""
			c.LegacyOnionPort = 0
			changed = true
		}
		if c.ListenAddress == "" {
			c.ListenAddress = "127.0.0.1"
			changed = true
		}
		if c.ProxyPort == 0 {
			c.ProxyPort = 9050
			changed = true
		}
		if c.BridgeHealthCheck.IntervalMinutes == 0 {
			c.BridgeHealthCheck.IntervalMinutes = 30
			changed = true
		}
		if changed {
			nb, _ := json.MarshalIndent(&c, "", "  ")
			if err := os.WriteFile(path, nb, 0644); err == nil {
				log.Printf("updated %s to the current config format", path)
			}
		}
		return &c, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	c := &config{
		ListenAddress: "127.0.0.1",
		ProxyPort:     9050,
		OnionServices: []onionMapping{{OnionPort: 22, ForwardTo: "127.0.0.1:22"}},
		Bridges:       []bridgeLine{},
		DNS:           dnsConfig{Enabled: false, OverTor: true},
		BridgeHealthCheck: bridgeHealthCheckConfig{
			Enabled:         false,
			IntervalMinutes: 30,
			OnDead:          "",
		},
	}
	b, _ = json.MarshalIndent(c, "", "  ")
	if err := os.WriteFile(path, b, 0644); err != nil {
		return nil, err
	}
	log.Printf("wrote default config to %s - edit it and restart if needed", path)
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

func extractLyrebird(binDir string) (string, error) {
	if err := os.MkdirAll(binDir, 0700); err != nil {
		return "", err
	}
	p := filepath.Join(binDir, "lyrebird.exe")
	if err := os.WriteFile(p, lyrebirdBin, 0755); err != nil {
		return "", err
	}
	return p, nil
}

type bridgeFeed struct {
	Updated string   `json:"updated"`
	Bridges []string `json:"bridges"`
}

func validateBridgeLines(lines []string) []string {
	var out []string
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) < 3 {
			continue
		}
		switch fields[0] {
		case "obfs4", "webtunnel":
			out = append(out, l)
		}
	}
	return out
}

// fetchBridges downloads and validates a bridge feed from an arbitrary,
// user-chosen URL over a plain (non-Tor) HTTPS connection.
func fetchBridges(url string) ([]string, string, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, "", err
	}
	var feed bridgeFeed
	if err := json.Unmarshal(body, &feed); err != nil {
		return nil, "", fmt.Errorf("response is not the expected JSON shape: %w", err)
	}
	valid := validateBridgeLines(feed.Bridges)
	if len(valid) == 0 {
		return nil, "", fmt.Errorf("fetched feed has no valid-looking obfs4/webtunnel bridge lines")
	}
	return valid, feed.Updated, nil
}

// networkLooksBlocked does a quick, lightweight probe (no Tor involved) to
// guess whether the network is blocking Tor before spending time on a full
// bootstrap attempt.
// runBridgeHealthCheck periodically verifies Tor can still reach the
// network while running with bridges, and runs an external command once
// when it transitions from working to not working (edge-triggered, so it
// doesn't spam the command on every failed check while still dead).
func runBridgeHealthCheck(ctx context.Context, cfg bridgeHealthCheckConfig, dial dialFunc) {
	if !cfg.Enabled {
		return
	}
	interval := time.Duration(cfg.IntervalMinutes) * time.Minute
	if interval <= 0 {
		interval = 30 * time.Minute
	}
	log.Printf("bridge health check enabled: checking every %s", interval)

	consecutiveFailures := 0
	wasDead := false
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			conn, err := dial(checkCtx, "tcp", "check.torproject.org:80")
			cancel()
			if err == nil {
				conn.Close()
				if wasDead {
					log.Println("bridge health check: connection recovered")
				}
				consecutiveFailures = 0
				wasDead = false
				continue
			}
			consecutiveFailures++
			log.Printf("bridge health check failed (%d in a row): %v", consecutiveFailures, err)
			if consecutiveFailures >= 2 && !wasDead {
				wasDead = true
				if cfg.OnDead != "" {
					log.Printf("bridges appear dead - running on_dead command: %s", cfg.OnDead)
					runExternalCommand(cfg.OnDead)
				} else {
					log.Println("bridges appear dead - no on_dead command configured")
				}
			}
		}
	}
}

func runExternalCommand(cmdline string) {
	cmd := exec.Command("cmd", "/C", cmdline)
	if err := cmd.Start(); err != nil {
		log.Printf("failed to start on_dead command: %v", err)
		return
	}
	go func() {
		if err := cmd.Wait(); err != nil {
			log.Printf("on_dead command exited with error: %v", err)
		}
	}()
}

func networkLooksBlocked() bool {
	conn, err := net.DialTimeout("tcp", "check.torproject.org:80", 10*time.Second)
	if err != nil {
		return true
	}
	conn.Close()
	return false
}

// runCheckBridges is the -check-bridges CLI mode: verify a bridge_source URL
// works, without starting Tor at all.
// runTestBridges tests each bridge line individually: starts the embedded
// Tor core with just that one bridge, tries to bootstrap, then closes it
// before moving to the next. Note: repeatedly starting/stopping the
// embedded core within one process run is not something used elsewhere in
// this program (the normal run path starts it exactly once) - if this
// behaves oddly, that's the first thing to suspect.
func runTestBridges(lines []bridgeLine, onDead string) {
	if len(lines) == 0 {
		fmt.Println("no bridges to test (empty config.json bridges, or empty -bridges-file)")
		return
	}

	base := filepath.Join(exeDir(), "slake")
	migrateOldFolder(base)
	os.MkdirAll(base, 0700)
	lyrebirdPath, err := extractLyrebird(filepath.Join(base, "bin"))
	if err != nil {
		log.Fatalf("extracting transport binary: %v", err)
	}
	if shortPath, serr := toShortPath(lyrebirdPath); serr == nil {
		lyrebirdPath = shortPath
	}

	aliveCount := 0
	for i, b := range lines {
		fmt.Printf("[%d/%d] testing: %s\n", i+1, len(lines), strings.Fields(b)[0]+" "+strings.Fields(b)[1])
		testDir := filepath.Join(base, "test-state")
		os.RemoveAll(testDir) // fresh state per bridge, avoid cross-contamination
		startConf := &tor.StartConf{
			ProcessCreator: libtor.Creator,
			DataDir:        testDir,
			ExtraArgs: []string{
				"--SocksPort", "127.0.0.1:19051",
				"--ClientTransportPlugin", "obfs4,webtunnel exec " + lyrebirdPath,
				"--UseBridges", "1",
				"--Bridge", b,
			},
		}
		t, err := tor.Start(nil, startConf)
		if err != nil {
			fmt.Printf("    FAILED to start: %v\n", err)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		dialer, derr := t.Dialer(ctx, &tor.DialConf{ProxyAddress: "127.0.0.1:19051"})
		ok := false
		if derr == nil {
			if conn, cerr := dialer.DialContext(ctx, "tcp", "check.torproject.org:80"); cerr == nil {
				conn.Close()
				ok = true
			}
		}
		cancel()
		t.Close()
		os.RemoveAll(testDir)
		if ok {
			fmt.Println("    OK")
			aliveCount++
		} else {
			fmt.Println("    dead")
		}
	}

	fmt.Printf("\n%d/%d bridge(s) working\n", aliveCount, len(lines))
	if aliveCount == 0 && onDead != "" {
		fmt.Printf("all bridges dead - running: %s\n", onDead)
		runExternalCommand(onDead)
	}
}

func runCheckBridges(urls []string) {
	if len(urls) == 0 {
		fmt.Println("no bridge_source.urls set in the config - nothing to check")
		return
	}
	anyOK := false
	for _, url := range urls {
		fmt.Printf("fetching %s ...\n", url)
		bridges, updated, err := fetchBridges(url)
		if err != nil {
			fmt.Printf("  FAILED: %v\n", err)
			continue
		}
		anyOK = true
		fmt.Printf("  OK: %d valid bridge line(s) found (feed updated: %s)\n", len(bridges), updated)
		for _, b := range bridges {
			fields := strings.Fields(b)
			fmt.Printf("    - %s ...\n", fields[0])
		}
	}
	if !anyOK {
		os.Exit(1)
	}
}

func pipeConns(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}

func proxyConn(a net.Conn, forwardTo string) {
	defer a.Close()
	b, err := net.DialTimeout("tcp", forwardTo, 15*time.Second)
	if err != nil {
		log.Printf("could not reach forward target %s: %v", forwardTo, err)
		return
	}
	pipeConns(a, b)
}

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func handleSocks5(conn net.Conn, br *bufio.Reader, dial dialFunc) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil { // no auth required
		return
	}
	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(br, reqHdr); err != nil {
		return
	}
	if reqHdr[1] != 0x01 { // only CONNECT supported
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch reqHdr[3] {
	case 0x01:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(br, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(br, lb); err != nil {
			return
		}
		nameBytes := make([]byte, lb[0])
		if _, err := io.ReadFull(br, nameBytes); err != nil {
			return
		}
		host = string(nameBytes)
	case 0x04:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(br, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(br, portBytes); err != nil {
		return
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])
	target := net.JoinHostPort(host, strconv.Itoa(port))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	remote, err := dial(ctx, "tcp", target)
	if err != nil {
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	pipeConns(conn, remote)
}

func handleHTTPConnect(conn net.Conn, br *bufio.Reader, dial dialFunc) {
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(line)
	if len(parts) < 2 || !strings.EqualFold(parts[0], "CONNECT") {
		conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return
	}
	target := parts[1]
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" || l == "\n" {
			break
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	remote, err := dial(ctx, "tcp", target)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	pipeConns(conn, remote)
}

func startProxy(listenAddr string, dial dialFunc) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	log.Printf("SOCKS5 + HTTP(CONNECT) proxy listening on %s", listenAddr)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("proxy accept error: %v", err)
				return
			}
			go func() {
				defer conn.Close()
				br := bufio.NewReader(conn)
				first, err := br.Peek(1)
				if err != nil {
					return
				}
				if first[0] == 0x05 {
					handleSocks5(conn, br, dial)
				} else {
					handleHTTPConnect(conn, br, dial)
				}
			}()
		}
	}()
	return nil
}

func torResolve(socksAddr, hostname string) (net.IP, error) {
	conn, err := net.DialTimeout("tcp", socksAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return nil, fmt.Errorf("socks5 handshake with tor failed")
	}
	req := []byte{0x05, 0xF0, 0x00, 0x03, byte(len(hostname))} // 0xF0 = Tor's RESOLVE extension
	req = append(req, []byte(hostname)...)
	req = append(req, 0x00, 0x00)
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	respHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHdr); err != nil {
		return nil, err
	}
	if respHdr[1] != 0x00 {
		return nil, fmt.Errorf("tor resolve failed, reply code %d", respHdr[1])
	}
	var ip net.IP
	switch respHdr[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, err
		}
		ip = net.IP(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, err
		}
		ip = net.IP(b)
	default:
		return nil, fmt.Errorf("unexpected address type %d in resolve reply", respHdr[3])
	}
	io.ReadFull(conn, make([]byte, 2)) // trailing (unused) port field
	return ip, nil
}

func startDNS(cfg dnsConfig, socksAddr string) {
	if !cfg.Enabled {
		return
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for _, q := range r.Question {
			if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
				continue
			}
			name := strings.TrimSuffix(q.Name, ".")
			var ip net.IP
			var err error
			if cfg.OverTor {
				ip, err = torResolve(socksAddr, name)
			} else {
				var ips []net.IP
				ips, err = net.LookupIP(name)
				if err == nil && len(ips) > 0 {
					ip = ips[0]
				}
			}
			if err != nil || ip == nil {
				continue
			}
			if q.Qtype == dns.TypeA && ip.To4() != nil {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   ip.To4(),
				})
			} else if q.Qtype == dns.TypeAAAA && ip.To4() == nil {
				m.Answer = append(m.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
					AAAA: ip.To16(),
				})
			}
		}
		w.WriteMsg(m)
	})

	for _, addr := range []string{"0.0.0.0:53", "127.0.0.1:53"} {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			log.Printf("DNS: %s unavailable (%v), trying next", addr, err)
			continue
		}
		srv := &dns.Server{PacketConn: pc, Handler: handler}
		go func(s *dns.Server, addr string) {
			log.Printf("embedded DNS server listening on %s (over_tor=%v)", addr, cfg.OverTor)
			if err := s.ActivateAndServe(); err != nil {
				log.Printf("DNS server on %s stopped: %v", addr, err)
			}
		}(srv, addr)
		return
	}
	log.Println("DNS: both 0.0.0.0:53 and 127.0.0.1:53 are taken - embedded DNS server disabled, everything else still works")
}

func runApp(ctx context.Context) {
	base := filepath.Join(exeDir(), "slake")
	migrateOldFolder(base)
	if err := os.MkdirAll(base, 0700); err != nil {
		log.Fatalf("cannot create data folder %s: %v", base, err)
	}
	log.Printf("working folder: %s", base)

	cfgPath := filepath.Join(base, "config.json")
	if _, statErr := os.Stat(cfgPath); statErr != nil {
		log.Printf("no existing config.json found at %s - will create a default one", cfgPath)
	} else {
		log.Printf("loading config from %s", cfgPath)
	}
	cfg, err := loadOrCreateConfig(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	key, err := loadOrCreateOnionKey(filepath.Join(base, "onion.key"))
	if err != nil {
		log.Fatalf("onion key: %v", err)
	}

	const internalSocksAddr = "127.0.0.1:19050"

	startConf := &tor.StartConf{
		ProcessCreator:    libtor.Creator,
		DataDir:           filepath.Join(base, "state"),
		RetainTempDataDir: true,
		NoAutoSocksPort:   true, // we set our own single SocksPort below instead
	}

	args := []string{"--SocksPort", internalSocksAddr}
	bridgeLines := cfg.Bridges
	usingBridges := len(bridgeLines) > 0

	if !usingBridges && len(cfg.BridgeSource.URLs) > 0 {
		log.Println("no bridges configured - checking whether the network looks blocked before trying...")
		if networkLooksBlocked() {
			log.Println("direct connection looks blocked - trying bridge_source.urls in order...")
			for _, url := range cfg.BridgeSource.URLs {
				fetched, updated, err := fetchBridges(url)
				if err != nil {
					log.Printf("  %s: %v", url, err)
					continue
				}
				log.Printf("  %s: got %d bridge(s) (feed updated: %s)", url, len(fetched), updated)
				bridgeLines = fetched
				usingBridges = true
				break
			}
			if !usingBridges {
				log.Println("none of the bridge_source.urls worked - continuing without bridges, it will likely fail to bootstrap.")
			}
		} else {
			log.Println("network looks reachable - trying a direct connection first")
		}
	}

	if usingBridges {
		log.Printf("starting with %d bridge line(s)", len(bridgeLines))
		lyrebirdPath, err := extractLyrebird(filepath.Join(base, "bin"))
		if err != nil {
			log.Fatalf("extracting transport binary: %v", err)
		}
		if shortPath, serr := toShortPath(lyrebirdPath); serr == nil {
			lyrebirdPath = shortPath
		} else {
			log.Printf("warning: could not get short path for %s (%v) - if your folder path has spaces, bridges may fail to start", lyrebirdPath, serr)
		}
		args = append(args, "--ClientTransportPlugin", "obfs4,webtunnel exec "+lyrebirdPath, "--UseBridges", "1")
		for _, b := range bridgeLines {
			args = append(args, "--Bridge", b)
		}
	} else {
		log.Println("no bridges configured - trying a direct connection first")
	}
	startConf.ExtraArgs = args

	log.Println("starting embedded Tor core (first run can take a while)...")
	t, err := tor.Start(nil, startConf)
	if err != nil {
		log.Fatalf("failed to start tor: %v", err)
	}
	defer t.Close()
	go func() { <-ctx.Done(); t.Close() }()

	timeout := 90 * time.Second
	if usingBridges {
		timeout = time.Duration(len(bridgeLines)) * 2 * time.Minute
		if timeout < 5*time.Minute {
			timeout = 5 * time.Minute
		}
		log.Printf("with %d bridge(s) configured, giving Tor up to %s to work through them", len(bridgeLines), timeout)
	}
	bootCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer, err := t.Dialer(bootCtx, &tor.DialConf{ProxyAddress: internalSocksAddr})
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
		log.Println("To use bridges: open slake/config.json, get bridge lines from")
		log.Println("Tor Browser's built-in bridge menu, https://bridges.torproject.org,")
		log.Println("or the @GetBridgesBot Telegram bot, paste them into \"bridges\", and")
		log.Println("restart this program.")
		log.Fatalf("bootstrap failed: %v", err)
	}
	log.Println("Tor bootstrapped, network reachable.")

	if err := startProxy(net.JoinHostPort(cfg.ListenAddress, strconv.Itoa(cfg.ProxyPort)), dialer.DialContext); err != nil {
		log.Printf("warning: could not start proxy on %s:%d: %v", cfg.ListenAddress, cfg.ProxyPort, err)
	}

	startDNS(cfg.DNS, internalSocksAddr)

	if usingBridges {
		go runBridgeHealthCheck(ctx, cfg.BridgeHealthCheck, dialer.DialContext)
	}

	if len(cfg.OnionServices) == 0 {
		log.Println("no onion_services configured - only the local proxy is active.")
		<-ctx.Done()
		return
	}

	kp := torutilEd25519.FromCryptoPrivateKey(key)

	var ports []*control.KeyVal
	var listeners []net.Listener
	for _, svc := range cfg.OnionServices {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			log.Fatalf("failed to open local listener for onion port %d: %v", svc.OnionPort, err)
		}
		localPort := ln.Addr().(*net.TCPAddr).Port
		ports = append(ports, &control.KeyVal{
			Key: strconv.Itoa(svc.OnionPort),
			Val: fmt.Sprintf("127.0.0.1:%d", localPort),
		})
		listeners = append(listeners, ln)
	}

	resp, err := t.Control.AddOnion(&control.AddOnionRequest{
		Key:   &control.ED25519Key{KeyPair: kp},
		Ports: ports,
	})
	if err != nil {
		log.Fatalf("failed to create hidden service: %v", err)
	}

	var addrLines []string
	for i, svc := range cfg.OnionServices {
		defer listeners[i].Close()
		line := fmt.Sprintf("%s.onion:%d -> %s", resp.ServiceID, svc.OnionPort, svc.ForwardTo)
		addrLines = append(addrLines, line)
		fmt.Println(line)

		go func(l net.Listener, forwardTo string) {
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				go proxyConn(conn, forwardTo)
			}
		}(listeners[i], svc.ForwardTo)
	}

	fmt.Println("========================================")
	addrFile := filepath.Join(base, "onion-address.txt")
	if err := os.WriteFile(addrFile, []byte(strings.Join(addrLines, "\n")+"\n"), 0644); err != nil {
		log.Printf("warning: could not save address to %s: %v", addrFile, err)
	}

	<-ctx.Done()
}

type program struct {
	cancel context.CancelFunc
}

func (p *program) Start(s service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	go runApp(ctx)
	return nil
}

func (p *program) Stop(s service.Service) error {
	if p.cancel != nil {
		p.cancel()
	}
	return nil
}

func main() {
	var svcAction, svcName, svcDesc string
	var checkBridges bool
	var testBridges bool
	var bridgesFile string
	var onDead string
	flag.StringVar(&svcAction, "service", "", "manage the Windows service: install, uninstall, start, stop, restart")
	flag.StringVar(&svcName, "service-name", "TorBundleWindows", "service name (used with -service install)")
	flag.StringVar(&svcDesc, "service-description", "Embedded Tor: SOCKS5/HTTP proxy, hidden service, DNS", "service description (used with -service install)")
	flag.BoolVar(&checkBridges, "check-bridges", false, "test the config's bridge_source.url and exit, without starting Tor")
	flag.BoolVar(&testBridges, "test-bridges", false, "test each bridge line individually (from config.json, or -bridges-file) and exit")
	flag.StringVar(&bridgesFile, "bridges-file", "", "with -test-bridges: test bridge lines from this file (one per line) instead of config.json")
	flag.StringVar(&onDead, "on-dead", "", "with -test-bridges: command/script to run if every tested bridge fails")
	flag.Parse()

	if checkBridges {
		base := filepath.Join(exeDir(), "slake")
		migrateOldFolder(base)
		os.MkdirAll(base, 0700)
		cfg, err := loadOrCreateConfig(filepath.Join(base, "config.json"))
		if err != nil {
			log.Fatalf("config: %v", err)
		}
		runCheckBridges(cfg.BridgeSource.URLs)
		return
	}

	if testBridges {
		var lines []bridgeLine
		if bridgesFile != "" {
			b, err := os.ReadFile(bridgesFile)
			if err != nil {
				log.Fatalf("reading %s: %v", bridgesFile, err)
			}
			for _, l := range strings.Split(string(b), "\n") {
				l = strings.TrimSpace(l)
				if l != "" {
					lines = append(lines, l)
				}
			}
		} else {
			base := filepath.Join(exeDir(), "slake")
			migrateOldFolder(base)
			os.MkdirAll(base, 0700)
			cfg, err := loadOrCreateConfig(filepath.Join(base, "config.json"))
			if err != nil {
				log.Fatalf("config: %v", err)
			}
			lines = cfg.Bridges
		}
		runTestBridges(lines, onDead)
		return
	}

	svcConfig := &service.Config{
		Name:        svcName,
		DisplayName: svcName,
		Description: svcDesc,
		// Executable left empty on purpose: kardianos/service then uses the
		// current executable's own path, whatever it's actually named.
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatalf("service setup: %v", err)
	}

	if svcAction != "" {
		if err := service.Control(s, svcAction); err != nil {
			log.Fatalf("service %s failed (try running as Administrator): %v", svcAction, err)
		}
		fmt.Printf("service %q: %s completed\n", svcName, svcAction)
		return
	}

	if err := s.Run(); err != nil {
		log.Fatalf("service run: %v", err)
	}
}
