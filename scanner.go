package main

import (
	"bytes"
	"context"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Result — найденный живой хост.
type Result struct {
	IP       netip.Addr
	Hostname string
	MAC      string
	Ports    []int
}

func (r Result) PortsString() string {
	parts := make([]string, len(r.Ports))
	for i, p := range r.Ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}

type Scanner struct {
	cfg     ScanConfig
	store   *Store
	trigger chan struct{}

	mu      sync.Mutex
	running bool
	next    time.Time
}

func NewScanner(cfg ScanConfig, store *Store) *Scanner {
	if slices.Contains(cfg.Methods, "ping") {
		if _, err := exec.LookPath("ping"); err != nil {
			log.Printf("предупреждение: команда ping не найдена, метод ping работать не будет")
		}
	}
	return &Scanner{cfg: cfg, store: store, trigger: make(chan struct{}, 1)}
}

// State возвращает признак идущего сканирования и время следующего запуска.
func (s *Scanner) State() (running bool, next time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running, s.next
}

// Trigger запускает внеочередное сканирование. false — если оно уже идёт.
func (s *Scanner) Trigger() bool {
	if running, _ := s.State(); running {
		return false
	}
	select {
	case s.trigger <- struct{}{}:
		return true
	default:
		return false
	}
}

// Run выполняет первое сканирование сразу, затем повторяет его через cfg.Interval.
func (s *Scanner) Run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-s.trigger:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}

		s.scanAll(ctx)

		s.mu.Lock()
		s.next = time.Now().Add(s.cfg.Interval)
		s.mu.Unlock()
		timer.Reset(s.cfg.Interval)
	}
}

func (s *Scanner) setRunning(v bool) {
	s.mu.Lock()
	s.running = v
	if v {
		s.next = time.Time{}
	}
	s.mu.Unlock()
}

func (s *Scanner) scanAll(ctx context.Context) {
	s.setRunning(true)
	defer s.setRunning(false)

	for _, p := range s.cfg.Prefixes {
		if ctx.Err() != nil {
			return
		}
		if err := s.scanNetwork(ctx, p); err != nil && ctx.Err() == nil {
			log.Printf("сканирование %s: %v", p, err)
		}
	}

	if s.cfg.ForgetAfter > 0 {
		n, err := s.store.Prune(time.Now().Add(-s.cfg.ForgetAfter))
		if err != nil {
			log.Printf("очистка старых записей: %v", err)
		} else if n > 0 {
			log.Printf("удалено устаревших записей: %d", n)
		}
	}
}

func (s *Scanner) scanNetwork(ctx context.Context, p netip.Prefix) error {
	started := time.Now()
	addrs := hostsIn(p)

	jobs := make(chan netip.Addr)
	out := make(chan Result)

	var wg sync.WaitGroup
	for i := 0; i < s.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range jobs {
				if r, ok := s.probe(ctx, a); ok {
					out <- r
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, a := range addrs {
			select {
			case jobs <- a:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(out)
	}()

	var up []Result
	for r := range out {
		up = append(up, r)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// MAC-адреса берём из ARP-кэша ОС: после проверок он уже заполнен.
	// Работает только для хостов в том же L2-сегменте.
	arp := readARP()
	for i := range up {
		up[i].MAC = arp[up[i].IP.String()]
	}
	sort.Slice(up, func(i, j int) bool { return up[i].IP.Less(up[j].IP) })

	finished := time.Now()
	if err := s.store.SaveScan(p.String(), started, finished, len(addrs), up); err != nil {
		return err
	}
	log.Printf("сеть %s: проверено %d, в сети %d, за %s",
		p, len(addrs), len(up), finished.Sub(started).Round(time.Millisecond))
	return nil
}

// hostsIn перечисляет адреса сети; для сетей до /30 включительно
// сетевой и широковещательный адреса исключаются.
func hostsIn(p netip.Prefix) []netip.Addr {
	p = p.Masked()
	var out []netip.Addr
	for a := p.Addr(); p.Contains(a); a = a.Next() {
		out = append(out, a)
	}
	if p.Bits() <= 30 && len(out) > 2 {
		out = out[1 : len(out)-1]
	}
	return out
}

// probe проверяет один адрес всеми настроенными методами.
func (s *Scanner) probe(ctx context.Context, a netip.Addr) (Result, bool) {
	res := Result{IP: a}
	alive := false

	for _, m := range s.cfg.Methods {
		switch m {
		case "ping":
			if pingHost(ctx, a, s.cfg.Timeout) {
				alive = true
			}
		case "tcp":
			ports, refused := tcpProbe(ctx, a, s.cfg.TCPPorts, s.cfg.Timeout)
			res.Ports = ports
			if len(ports) > 0 || refused {
				alive = true
			}
		}
	}
	if !alive {
		return res, false
	}

	if s.cfg.ResolveNames {
		res.Hostname = lookupName(ctx, a.String())
	}
	return res, true
}

func pingArgs(ip string, timeout time.Duration) []string {
	switch runtime.GOOS {
	case "windows":
		return []string{"-n", "1", "-w", strconv.Itoa(int(timeout.Milliseconds())), ip}
	case "darwin", "freebsd":
		return []string{"-c", "1", "-W", strconv.Itoa(int(timeout.Milliseconds())), ip}
	default: // Linux: -W в секундах
		sec := int((timeout + time.Second - 1) / time.Second)
		if sec < 1 {
			sec = 1
		}
		return []string{"-c", "1", "-W", strconv.Itoa(sec), ip}
	}
}

func pingHost(ctx context.Context, ip netip.Addr, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(ctx, timeout+2*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ping", pingArgs(ip.String(), timeout)...).Output()
	if err != nil {
		return false
	}
	// На Windows ответ "Destination host unreachable" тоже даёт код 0,
	// поэтому требуем настоящий эхо-ответ (в нём всегда есть "TTL=").
	return bytes.Contains(bytes.ToLower(out), []byte("ttl="))
}

// tcpProbe пробует подключиться к портам. Возвращает открытые порты и признак того,
// что хоть один порт ответил отказом (RST) — это тоже значит, что хост жив.
func tcpProbe(ctx context.Context, ip netip.Addr, ports []int, timeout time.Duration) (open []int, refused bool) {
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for _, port := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			d := net.Dialer{Timeout: timeout}
			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))

			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				conn.Close()
				open = append(open, port)
			case strings.Contains(strings.ToLower(err.Error()), "refused"):
				refused = true
			}
		}(port)
	}
	wg.Wait()
	sort.Ints(open)
	return open, refused
}

func lookupName(ctx context.Context, ip string) string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

var (
	ipRe  = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	macRe = regexp.MustCompile(`(?i)\b[0-9a-f]{1,2}(?:[:-][0-9a-f]{1,2}){5}\b`)
)

// readARP возвращает таблицу соответствия IP → MAC из ARP-кэша операционной системы.
func readARP() map[string]string {
	var text string
	switch runtime.GOOS {
	case "linux":
		if b, err := os.ReadFile("/proc/net/arp"); err == nil {
			text = string(b)
		}
	case "windows":
		if b, err := exec.Command("arp", "-a").Output(); err == nil {
			text = string(b)
		}
	default:
		if b, err := exec.Command("arp", "-an").Output(); err == nil {
			text = string(b)
		}
	}
	return parseARP(text)
}

func parseARP(text string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(text, "\n") {
		ip := ipRe.FindString(line)
		mac := macRe.FindString(line)
		if ip == "" || mac == "" {
			continue
		}
		mac = normMAC(mac)
		if mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
			continue // неполная запись или broadcast
		}
		m[ip] = mac
	}
	return m
}

// normMAC приводит MAC к виду aa:bb:cc:dd:ee:ff (macOS отдаёт октеты без ведущих нулей).
func normMAC(s string) string {
	parts := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return r == ':' || r == '-' })
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}
