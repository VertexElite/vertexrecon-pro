package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════
//  VERTEX-NET — Go Network Recon Engine
//  Concurrent port scanning, /proc/net deep decode, DNS recon,
//  IP reputation lookups, live connection monitoring
// ═══════════════════════════════════════════════════════════════

const (
	colorRed    = "\033[0;31m"
	colorGreen  = "\033[0;32m"
	colorYellow = "\033[1;33m"
	colorCyan   = "\033[0;36m"
	colorPurple = "\033[0;35m"
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
)

// Known C2/malware ports — OMEGATECH, Cobalt Strike, Metasploit, common RATs
var suspiciousPorts = map[uint16]string{
	1337:  "leet-backdoor",
	2002:  "OMEGATECH-C2",
	2004:  "OMEGATECH-C2",
	2244:  "OMEGATECH-C2",
	3232:  "OMEGATECH-C2",
	3389:  "RDP",
	4444:  "Metasploit-default",
	4545:  "internal-RAT",
	5555:  "ADB-remote",
	6565:  "OMEGATECH-C2",
	6666:  "IRC-backdoor",
	7273:  "OMEGATECH-C2",
	7777:  "common-RAT",
	8443:  "alt-HTTPS-C2",
	8888:  "common-RAT",
	9001:  "Tor-relay",
	9090:  "Zeus-C2",
	9999:  "common-RAT",
	12345: "NetBus",
	31337: "Back-Orifice",
	34567: "OMEGATECH-C2",
	50050: "Cobalt-Strike",
}

// IOC domains from OMEGATECH/GHOSTYNETWORKS campaign
var iocDomains = []string{
	"scan.aryamint.com", "mail.talruit.com", "mpwirerope.com",
	"ethara.org", "talruit.com", "aryamint.com",
}

// TCP states from /proc/net/tcp
var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
	"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
	"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
	"0A": "LISTEN", "0B": "CLOSING",
}

type Connection struct {
	Proto     string
	LocalIP   string
	LocalPort uint16
	RemoteIP  string
	RemPort   uint16
	State     string
	UID       int
	Inode     string
}

type ScanResult struct {
	Port    int
	Open    bool
	Service string
	Banner  string
}

type IPInfo struct {
	IP       string `json:"ip"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Org      string `json:"org"`
	Timezone string `json:"timezone"`
	Hostname string `json:"hostname"`
}

// ─── /proc/net deep parser ───────────────────────────────────

func hexToIP(hexStr string) string {
	if len(hexStr) == 8 {
		b, _ := hex.DecodeString(hexStr)
		if len(b) == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
		}
	}
	if len(hexStr) == 32 {
		b, _ := hex.DecodeString(hexStr)
		if len(b) == 16 {
			// Reverse each 4-byte group for Android/Linux endianness
			for i := 0; i < 16; i += 4 {
				b[i], b[i+3] = b[i+3], b[i]
				b[i+1], b[i+2] = b[i+2], b[i+1]
			}
			ip := net.IP(b)
			return ip.String()
		}
	}
	return hexStr
}

func parseAddr(addr string) (string, uint16) {
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		return "?", 0
	}
	ip := hexToIP(parts[0])
	port, _ := strconv.ParseUint(parts[1], 16, 16)
	return ip, uint16(port)
}

func parseProcNet(proto string) []Connection {
	path := "/proc/net/" + proto
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var conns []Connection
	scanner := bufio.NewScanner(file)
	scanner.Scan() // skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		localIP, localPort := parseAddr(fields[1])
		remoteIP, remPort := parseAddr(fields[2])
		state := tcpStates[fields[3]]
		if state == "" {
			state = fields[3]
		}

		uid, _ := strconv.Atoi(fields[7])

		inode := ""
		if len(fields) > 9 {
			inode = fields[9]
		}

		conns = append(conns, Connection{
			Proto:     proto,
			LocalIP:   localIP,
			LocalPort: localPort,
			RemoteIP:  remoteIP,
			RemPort:   remPort,
			State:     state,
			UID:       uid,
			Inode:     inode,
		})
	}
	return conns
}

func deepConnectionScan() {
	fmt.Printf("\n%s══ DEEP CONNECTION ANALYSIS ══%s\n\n", colorCyan, colorReset)

	allConns := []Connection{}
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		conns := parseProcNet(proto)
		allConns = append(allConns, conns...)
	}

	// Stats
	stateCounts := map[string]int{}
	protoCounts := map[string]int{}
	suspiciousConns := []Connection{}
	uniqueRemotes := map[string]bool{}

	for _, c := range allConns {
		stateCounts[c.State]++
		protoCounts[c.Proto]++

		if c.RemoteIP != "0.0.0.0" && c.RemoteIP != "::" && c.RemoteIP != "127.0.0.1" && c.RemoteIP != "::1" {
			uniqueRemotes[c.RemoteIP] = true
		}

		if tag, ok := suspiciousPorts[c.RemPort]; ok {
			c.State = c.State + " [" + tag + "]"
			suspiciousConns = append(suspiciousConns, c)
		}
		if tag, ok := suspiciousPorts[c.LocalPort]; ok {
			c.State = c.State + " [" + tag + "]"
			suspiciousConns = append(suspiciousConns, c)
		}
	}

	fmt.Printf("  %sTotal connections:%s %d\n", colorBold, colorReset, len(allConns))
	fmt.Printf("  %sUnique remote IPs:%s %d\n", colorBold, colorReset, len(uniqueRemotes))

	fmt.Printf("\n  %sBy state:%s\n", colorBold, colorReset)
	for state, count := range stateCounts {
		fmt.Printf("    %-14s %d\n", state, count)
	}

	fmt.Printf("\n  %sBy protocol:%s\n", colorBold, colorReset)
	for proto, count := range protoCounts {
		fmt.Printf("    %-8s %d\n", proto, count)
	}

	// Active connections (non-loopback)
	fmt.Printf("\n  %sActive external connections:%s\n", colorBold, colorReset)
	for _, c := range allConns {
		if c.RemoteIP == "0.0.0.0" || c.RemoteIP == "::" ||
			c.RemoteIP == "127.0.0.1" || c.RemoteIP == "::1" {
			continue
		}
		if c.State != "LISTEN" && c.State != "TIME_WAIT" {
			flag := ""
			if _, ok := suspiciousPorts[c.RemPort]; ok {
				flag = fmt.Sprintf(" %s⚠ SUSPICIOUS%s", colorRed, colorReset)
			}
			fmt.Printf("    %s%-13s%s %s:%d → %s:%d (uid:%d)%s\n",
				colorYellow, c.State, colorReset,
				c.LocalIP, c.LocalPort, c.RemoteIP, c.RemPort, c.UID, flag)
		}
	}

	// Listeners
	fmt.Printf("\n  %sListening ports:%s\n", colorBold, colorReset)
	for _, c := range allConns {
		if c.State == "LISTEN" {
			fmt.Printf("    %s[LISTEN]%s %s:%d (%s)\n",
				colorGreen, colorReset, c.LocalIP, c.LocalPort, c.Proto)
		}
	}

	// Suspicious
	if len(suspiciousConns) > 0 {
		fmt.Printf("\n  %s%s⚠ SUSPICIOUS CONNECTIONS:%s\n", colorRed, colorBold, colorReset)
		for _, c := range suspiciousConns {
			fmt.Printf("    %s%s%s %s:%d → %s:%d\n",
				colorRed, c.State, colorReset,
				c.LocalIP, c.LocalPort, c.RemoteIP, c.RemPort)
		}
	} else {
		fmt.Printf("\n  %s[✓] No known suspicious ports detected%s\n", colorGreen, colorReset)
	}
}

// ─── Concurrent port scanner ─────────────────────────────────

func scanPort(host string, port int, timeout time.Duration) ScanResult {
	result := ScanResult{Port: port}
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return result
	}
	defer conn.Close()

	result.Open = true
	result.Service = guessService(port)

	// Banner grab
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	banner := make([]byte, 1024)
	n, _ := conn.Read(banner)
	if n > 0 {
		result.Banner = strings.TrimSpace(string(banner[:n]))
		if len(result.Banner) > 80 {
			result.Banner = result.Banner[:80] + "..."
		}
	}

	return result
}

func concurrentScan(host string, ports []int, workers int, timeout time.Duration) []ScanResult {
	var results []ScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	portChan := make(chan int, len(ports))
	for _, p := range ports {
		portChan <- p
	}
	close(portChan)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				r := scanPort(host, port, timeout)
				if r.Open {
					mu.Lock()
					results = append(results, r)
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	return results
}

func guessService(port int) string {
	services := map[int]string{
		21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
		80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
		993: "IMAPS", 995: "POP3S", 3306: "MySQL", 5432: "PostgreSQL",
		6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
	}
	if s, ok := services[port]; ok {
		return s
	}
	if tag, ok := suspiciousPorts[uint16(port)]; ok {
		return tag
	}
	return "unknown"
}

// ─── DNS deep recon ──────────────────────────────────────────

func dnsRecon(domain string) {
	fmt.Printf("\n%s══ DNS RECON: %s ══%s\n\n", colorCyan, domain, colorReset)

	types := []string{"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"}
	for _, t := range types {
		var records []string
		var err error

		switch t {
		case "A":
			ips, e := net.LookupHost(domain)
			records, err = ips, e
		case "AAAA":
			ips, e := net.LookupIP(domain)
			err = e
			for _, ip := range ips {
				if ip.To4() == nil {
					records = append(records, ip.String())
				}
			}
		case "MX":
			mxs, e := net.LookupMX(domain)
			err = e
			for _, mx := range mxs {
				records = append(records, fmt.Sprintf("%s (pref:%d)", mx.Host, mx.Pref))
			}
		case "NS":
			nss, e := net.LookupNS(domain)
			err = e
			for _, ns := range nss {
				records = append(records, ns.Host)
			}
		case "TXT":
			txts, e := net.LookupTXT(domain)
			records, err = txts, e
		case "CNAME":
			cname, e := net.LookupCNAME(domain)
			err = e
			if cname != "" && cname != domain+"." {
				records = []string{cname}
			}
		}

		if err != nil || len(records) == 0 {
			continue
		}
		for _, r := range records {
			fmt.Printf("  %s%-6s%s %s\n", colorYellow, t, colorReset, r)
		}
	}

	// Reverse DNS on A records
	ips, err := net.LookupHost(domain)
	if err == nil {
		fmt.Printf("\n  %sReverse DNS:%s\n", colorBold, colorReset)
		for _, ip := range ips {
			names, err := net.LookupAddr(ip)
			if err == nil && len(names) > 0 {
				fmt.Printf("    %s → %s\n", ip, strings.Join(names, ", "))
			} else {
				fmt.Printf("    %s → (no PTR)\n", ip)
			}
		}
	}

	// TLS cert inspection
	fmt.Printf("\n  %sTLS Certificate:%s\n", colorBold, colorReset)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", domain+":443", &tls.Config{InsecureSkipVerify: true})
	if err == nil {
		defer conn.Close()
		for _, cert := range conn.ConnectionState().PeerCertificates {
			fmt.Printf("    Subject:  %s\n", cert.Subject.CommonName)
			fmt.Printf("    Issuer:   %s\n", cert.Issuer.CommonName)
			fmt.Printf("    NotAfter: %s\n", cert.NotAfter.Format("2006-01-02"))
			fmt.Printf("    SANs:     %s\n", strings.Join(cert.DNSNames, ", "))
			break
		}
	}
}

// ─── IP reputation lookup ────────────────────────────────────

func lookupIP(ip string) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://ipinfo.io/" + ip + "/json")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var info IPInfo
	json.Unmarshal(body, &info)

	fmt.Printf("    IP:       %s\n", info.IP)
	fmt.Printf("    Org:      %s\n", info.Org)
	fmt.Printf("    Location: %s, %s, %s\n", info.City, info.Region, info.Country)
	if info.Hostname != "" {
		fmt.Printf("    Hostname: %s\n", info.Hostname)
	}
}

// ─── IOC domain check ────────────────────────────────────────

func checkIOCDomains() {
	fmt.Printf("\n%s══ THREAT IOC DOMAIN CHECK ══%s\n\n", colorCyan, colorReset)

	for _, domain := range iocDomains {
		ips, err := net.LookupHost(domain)
		if err != nil || len(ips) == 0 {
			fmt.Printf("  %s[✓]%s %s — not resolving (clean)\n", colorGreen, colorReset, domain)
		} else {
			fmt.Printf("  %s[!] %s resolves to: %s — ACTIVE IOC!%s\n",
				colorRed, domain, strings.Join(ips, ", "), colorReset)
		}
	}
}

// ─── HTTP security headers ───────────────────────────────────

func checkHTTPHeaders(url string) {
	fmt.Printf("\n%s══ HTTP SECURITY HEADERS: %s ══%s\n\n", colorCyan, url, colorReset)

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("  %s[!] Cannot reach: %s%s\n", colorRed, err, colorReset)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("  Status: %s\n\n", resp.Status)

	secHeaders := map[string]struct {
		present  bool
		critical bool
	}{
		"Strict-Transport-Security": {false, true},
		"Content-Security-Policy":   {false, true},
		"X-Frame-Options":           {false, true},
		"X-Content-Type-Options":    {false, true},
		"X-XSS-Protection":          {false, false},
		"Referrer-Policy":           {false, false},
		"Permissions-Policy":        {false, false},
	}

	for name := range secHeaders {
		val := resp.Header.Get(name)
		entry := secHeaders[name]
		if val != "" {
			entry.present = true
			secHeaders[name] = entry
			fmt.Printf("  %s[✓]%s %-35s %s\n", colorGreen, colorReset, name, truncate(val, 50))
		}
	}

	for name, entry := range secHeaders {
		if !entry.present {
			severity := colorYellow
			tag := "MISSING"
			if entry.critical {
				severity = colorRed
				tag = "CRITICAL-MISSING"
			}
			fmt.Printf("  %s[!] %-35s %s%s\n", severity, name, tag, colorReset)
		}
	}

	// Leak check
	server := resp.Header.Get("Server")
	powered := resp.Header.Get("X-Powered-By")
	if server != "" {
		fmt.Printf("\n  %s[!] Server header leaks: %s%s\n", colorYellow, server, colorReset)
	}
	if powered != "" {
		fmt.Printf("  %s[!] X-Powered-By leaks: %s%s\n", colorYellow, powered, colorReset)
	}
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// ─── Live connection monitor ─────────────────────────────────

func liveMonitor() {
	fmt.Printf("\n%s══ LIVE CONNECTION MONITOR (Ctrl+C to stop) ══%s\n\n", colorCyan, colorReset)

	seen := map[string]bool{}

	// Initial snapshot
	for _, proto := range []string{"tcp", "tcp6"} {
		for _, c := range parseProcNet(proto) {
			key := fmt.Sprintf("%s:%d->%s:%d", c.LocalIP, c.LocalPort, c.RemoteIP, c.RemPort)
			seen[key] = true
		}
	}

	for {
		time.Sleep(2 * time.Second)
		for _, proto := range []string{"tcp", "tcp6"} {
			for _, c := range parseProcNet(proto) {
				if c.RemoteIP == "0.0.0.0" || c.RemoteIP == "::" {
					continue
				}
				key := fmt.Sprintf("%s:%d->%s:%d", c.LocalIP, c.LocalPort, c.RemoteIP, c.RemPort)
				if !seen[key] {
					seen[key] = true
					flag := ""
					if tag, ok := suspiciousPorts[c.RemPort]; ok {
						flag = fmt.Sprintf(" %s⚠ %s%s", colorRed, tag, colorReset)
					}
					fmt.Printf("  %s[%s]%s %sNEW%s %s :%d → %s:%d%s\n",
						colorCyan, time.Now().Format("15:04:05"), colorReset,
						colorYellow, colorReset,
						c.LocalIP, c.LocalPort, c.RemoteIP, c.RemPort, flag)
				}
			}
		}
	}
}

// ─── Proc filesystem deep scan ───────────────────────────────

func procDeepScan() {
	fmt.Printf("\n%s══ /proc DEEP FILESYSTEM SCAN ══%s\n\n", colorCyan, colorReset)

	// ARP table
	fmt.Printf("  %sARP table (local network devices):%s\n", colorBold, colorReset)
	arpData, _ := os.ReadFile("/proc/net/arp")
	lines := strings.Split(string(arpData), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 6 {
			fmt.Printf("    %s → %s (%s)\n", fields[0], fields[3], fields[5])
		}
	}

	// Routing table
	fmt.Printf("\n  %sRouting table:%s\n", colorBold, colorReset)
	routeData, _ := os.ReadFile("/proc/net/route")
	routeLines := strings.Split(string(routeData), "\n")
	for _, line := range routeLines[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 8 {
			dest := procNetIPDecode(fields[1])
			gw := procNetIPDecode(fields[2])
			mask := procNetIPDecode(fields[7])
			fmt.Printf("    %s → gw %s mask %s dev %s\n", dest, gw, mask, fields[0])
		}
	}

	// Network stats
	fmt.Printf("\n  %sNetwork device stats:%s\n", colorBold, colorReset)
	devData, _ := os.ReadFile("/proc/net/dev")
	devLines := strings.Split(string(devData), "\n")
	for _, line := range devLines[2:] {
		fields := strings.Fields(line)
		if len(fields) >= 10 {
			iface := strings.TrimSuffix(fields[0], ":")
			rxBytes, _ := strconv.ParseUint(fields[1], 10, 64)
			txBytes, _ := strconv.ParseUint(fields[9], 10, 64)
			if rxBytes > 0 || txBytes > 0 {
				fmt.Printf("    %-12s RX: %s  TX: %s\n",
					iface, humanBytes(rxBytes), humanBytes(txBytes))
			}
		}
	}

	// Socket stats
	fmt.Printf("\n  %sSocket statistics (/proc/net/sockstat):%s\n", colorBold, colorReset)
	sockData, _ := os.ReadFile("/proc/net/sockstat")
	fmt.Printf("    %s\n", strings.ReplaceAll(string(sockData), "\n", "\n    "))
}

func procNetIPDecode(hexIP string) string {
	if len(hexIP) != 8 {
		return hexIP
	}
	val, _ := strconv.ParseUint(hexIP, 16, 32)
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(val))
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func humanBytes(b uint64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	f := float64(b)
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

// ─── Main ────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		fmt.Printf(`
%sVERTEX-NET%s — Go Network Recon Engine

Usage:
  vertex-net conns          Deep connection analysis
  vertex-net scan <host>    Concurrent port scan (top 1000)
  vertex-net dns <domain>   Full DNS recon
  vertex-net headers <url>  HTTP security header check
  vertex-net ioc            Check known malware IOC domains
  vertex-net proc           Deep /proc filesystem scan
  vertex-net monitor        Live connection monitor
  vertex-net lookup <ip>    IP reputation lookup
  vertex-net full <domain>  Run everything against a target

`, colorPurple, colorReset)
		os.Exit(0)
	}

	cmd := os.Args[1]
	_ = filepath.Base // suppress unused import

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = ctx

	switch cmd {
	case "conns":
		deepConnectionScan()

	case "scan":
		if len(os.Args) < 3 {
			fmt.Println("Usage: vertex-net scan <host>")
			os.Exit(1)
		}
		host := os.Args[2]
		fmt.Printf("\n%s══ PORT SCAN: %s ══%s\n\n", colorCyan, host, colorReset)
		fmt.Printf("  Scanning top 1000 ports with 200 workers...\n\n")

		ports := topPorts()
		results := concurrentScan(host, ports, 200, 3*time.Second)

		if len(results) == 0 {
			fmt.Printf("  No open ports found.\n")
		}
		for _, r := range results {
			flag := ""
			if _, ok := suspiciousPorts[uint16(r.Port)]; ok {
				flag = fmt.Sprintf(" %s⚠ SUSPICIOUS%s", colorRed, colorReset)
			}
			bannerStr := ""
			if r.Banner != "" {
				bannerStr = fmt.Sprintf(" | %s", r.Banner)
			}
			fmt.Printf("  %s[OPEN]%s %5d/tcp %-15s%s%s\n",
				colorGreen, colorReset, r.Port, r.Service, bannerStr, flag)
		}
		fmt.Printf("\n  %d open / %d scanned\n", len(results), len(ports))

	case "dns":
		if len(os.Args) < 3 {
			fmt.Println("Usage: vertex-net dns <domain>")
			os.Exit(1)
		}
		dnsRecon(os.Args[2])

	case "headers":
		if len(os.Args) < 3 {
			fmt.Println("Usage: vertex-net headers <url>")
			os.Exit(1)
		}
		url := os.Args[2]
		if !strings.HasPrefix(url, "http") {
			url = "https://" + url
		}
		checkHTTPHeaders(url)

	case "ioc":
		checkIOCDomains()

	case "proc":
		procDeepScan()

	case "monitor":
		liveMonitor()

	case "lookup":
		if len(os.Args) < 3 {
			fmt.Println("Usage: vertex-net lookup <ip>")
			os.Exit(1)
		}
		fmt.Printf("\n%s══ IP LOOKUP: %s ══%s\n\n", colorCyan, os.Args[2], colorReset)
		lookupIP(os.Args[2])

	case "full":
		if len(os.Args) < 3 {
			fmt.Println("Usage: vertex-net full <domain>")
			os.Exit(1)
		}
		target := os.Args[2]
		deepConnectionScan()
		procDeepScan()
		checkIOCDomains()
		dnsRecon(target)
		checkHTTPHeaders("https://" + target)
		fmt.Printf("\n%s══ PORT SCAN: %s ══%s\n", colorCyan, target, colorReset)
		results := concurrentScan(target, topPorts(), 200, 3*time.Second)
		for _, r := range results {
			fmt.Printf("  %s[OPEN]%s %5d/tcp %s\n", colorGreen, colorReset, r.Port, r.Service)
		}
	}

	fmt.Println()
}

func topPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 81, 110, 111, 113, 135, 139, 143, 179, 199,
		443, 445, 465, 514, 515, 548, 554, 587, 646, 993, 995,
		1025, 1026, 1027, 1028, 1029, 1110, 1337, 1433, 1521, 1723, 1883,
		2000, 2001, 2002, 2004, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
		2222, 2244, 3000, 3128, 3232, 3306, 3389, 3690, 4000, 4444, 4443,
		4545, 4848, 5000, 5432, 5555, 5601, 5672, 5900, 5984, 6000, 6379,
		6565, 6666, 6667, 7001, 7273, 7474, 7777, 8000, 8008, 8080, 8081,
		8443, 8444, 8888, 8983, 9000, 9001, 9042, 9090, 9200, 9300, 9418,
		9999, 10000, 11211, 12345, 15672, 27017, 28017, 31337, 34567, 50050,
	}
}
