package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

var debug = os.Getenv("DEBUG") == "1"

// allPorts controls whether we register every detected port or just the first one.
var allPorts = flag.Bool(
	"all-ports",
	false,
	"register every exposed/published port instead of just the first one",
)

func init() { rand.Seed(time.Now().UnixNano()) }

// ----------------------------------------------------------------------
// Service
// ----------------------------------------------------------------------

type Service struct {
	ID, Name   string
	IP         string
	Port       int
	Tags       []string
	HTTPPath   string
	TCPCheck   bool
	TTL        string
	Interval   string
	Timeout    string
	DeregAfter string
	ttlValid   bool
}

// ----------------------------------------------------------------------
// Consul backend
// ----------------------------------------------------------------------

type Backend interface {
	Register(*Service) error
	Deregister(*Service) error
	PassTTL(*Service) error
}

type consulBackend struct {
	addr   string
	client *http.Client
	scheme string
}

type httpBackoff struct{ min, max time.Duration }

func (b httpBackoff) next(prev time.Duration) time.Duration {
	if prev == 0 {
		return b.min
	}
	d := prev * 2
	if d > b.max {
		d = b.max
	}
	jitter := d / 10
	if jitter == 0 {
		return d
	}
	return d - jitter + time.Duration(rand.Int63n(int64(2*jitter)))
}

func newConsulBackend(addr string, insecure bool) *consulBackend {
	if addr == "" {
		addr = "consul:8500"
	}
	scheme := "http://"
	switch {
	case strings.HasPrefix(addr, "https://"):
		scheme = "https://"
		addr = strings.TrimPrefix(addr, "https://")
	case strings.HasPrefix(addr, "http://"):
		addr = strings.TrimPrefix(addr, "http://")
	}
	addr = strings.TrimSuffix(addr, "/")

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}}
	cl := &http.Client{
		Timeout:       10 * time.Second,
		Transport:     tr,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &consulBackend{addr: addr, client: cl, scheme: scheme}
}

func (c *consulBackend) put(ctx context.Context, path string, payload any) error {
	var data []byte
	if payload != nil {
		var err error
		if data, err = json.Marshal(payload); err != nil {
			return err
		}
	}

	urlStr := c.scheme + c.addr + path
	back := httpBackoff{min: 500 * time.Millisecond, max: 4 * time.Second}
	var wait time.Duration

	for attempt := 0; attempt < 3; attempt++ {
		if debug {
			log.Printf("→ PUT %s (%dB) attempt=%d", urlStr, len(data), attempt+1)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPut, urlStr, bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.client.Do(req)
		if err == nil {
			if resp.StatusCode < 300 {
				resp.Body.Close()
				return nil
			}
			msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			err = fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(msg)))
		}

		if attempt == 2 {
			return err
		}
		wait = back.next(wait)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (c *consulBackend) buildCheck(s *Service) map[string]any {
	dereg := firstNonEmpty(s.DeregAfter, "1m")

	switch {
	case s.ttlValid:
		return map[string]any{
			"TTL":                            s.TTL,
			"DeregisterCriticalServiceAfter": dereg,
		}
	case s.HTTPPath != "":
		target := s.HTTPPath
		if !strings.HasPrefix(target, "http") {
			if !strings.HasPrefix(target, "/") {
				target = "/" + target
			}
			target = fmt.Sprintf("http://%s:%d%s", s.IP, s.Port, target)
		}
		return map[string]any{
			"HTTP":                           target,
			"Interval":                       firstNonEmpty(s.Interval, "10s"),
			"Timeout":                        firstNonEmpty(s.Timeout, "2s"),
			"DeregisterCriticalServiceAfter": dereg,
		}
	case s.TCPCheck:
		return map[string]any{
			"TCP":                            fmt.Sprintf("%s:%d", s.IP, s.Port),
			"Interval":                       firstNonEmpty(s.Interval, "10s"),
			"Timeout":                        firstNonEmpty(s.Timeout, "2s"),
			"DeregisterCriticalServiceAfter": dereg,
		}
	default:
		return nil
	}
}

func (c *consulBackend) Register(s *Service) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	payload := map[string]any{
		"ID":      s.ID,
		"Name":    s.Name,
		"Address": s.IP,
		"Port":    s.Port,
		"Tags":    s.Tags,
	}
	if chk := c.buildCheck(s); chk != nil {
		payload["Check"] = chk
	}
	return c.put(ctx, "/v1/agent/service/register", payload)
}

func (c *consulBackend) Deregister(s *Service) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return c.put(ctx, "/v1/agent/service/deregister/"+url.PathEscape(s.ID), nil)
}

func (c *consulBackend) PassTTL(s *Service) error {
	if !s.ttlValid {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.put(ctx, "/v1/agent/check/pass/service:"+url.PathEscape(s.ID), nil)
}

// ----------------------------------------------------------------------
// Bridge
// ----------------------------------------------------------------------

type regEntry struct {
	services []*Service
	cancel   context.CancelFunc
	mu       sync.Mutex
}

type Bridge struct {
	cli *client.Client
	be  Backend

	mu  sync.Mutex
	reg map[string]*regEntry
	wg  sync.WaitGroup

	rootCtx context.Context
}

func newBridge(be Backend) (*Bridge, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	return &Bridge{cli: cli, be: be, reg: make(map[string]*regEntry)}, nil
}

func (b *Bridge) Close() error { return b.cli.Close() }

func (b *Bridge) Run(ctx context.Context) error {
	b.rootCtx = ctx

	f := filters.NewArgs()
	f.Add("type", "container")
	for _, ev := range []string{"start", "die", "destroy", "stop", "kill"} {
		f.Add("event", ev)
	}

	for {
		evCtx, cancel := context.WithCancel(ctx)
		msgs, errs := b.cli.Events(evCtx, events.ListOptions{Filters: f})

		if err := b.initialScan(evCtx); err != nil {
			cancel()
			return err
		}

		if err := b.eventLoop(evCtx, msgs, errs); err != nil {
			cancel()
			if errors.Is(err, context.Canceled) {
				b.wg.Wait()
				return err
			}
			log.Printf("event stream error: %v – reconnecting in 2s", err)

			b.mu.Lock()
			for cid, entry := range b.reg {
				entry.cancel()
				delete(b.reg, cid)
			}
			b.mu.Unlock()

			b.wg.Wait()
			time.Sleep(2 * time.Second)
			continue
		}

		cancel()
		b.wg.Wait()
		return nil
	}
}

func (b *Bridge) initialScan(ctx context.Context) error {
	list, err := b.cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return err
	}
	for _, c := range list {
		b.mu.Lock()
		_, exists := b.reg[c.ID]
		b.mu.Unlock()
		if exists {
			continue
		}
		go b.handleStart(ctx, c.ID)
	}
	return nil
}

func (b *Bridge) eventLoop(ctx context.Context, msgs <-chan events.Message, errs <-chan error) error {
	for {
		select {
		case m, ok := <-msgs:
			if !ok {
				return io.EOF
			}
			switch m.Action {
			case "start":
				go b.handleStart(ctx, m.ID)
			case "die", "destroy", "stop", "kill":
				go b.handleStop(m.ID)
			}
		case err, ok := <-errs:
			if !ok {
				return io.EOF
			}
			if err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func hasGlobalIgnore(env []string, labels map[string]string) bool {
	for _, e := range env {
		if strings.HasPrefix(e, "SERVICE_IGNORE=") &&
			strings.TrimSpace(strings.TrimPrefix(e, "SERVICE_IGNORE=")) == "true" {
			return true
		}
	}
	return labels["SERVICE_IGNORE"] == "true"
}

func (b *Bridge) handleStart(parentCtx context.Context, cid string) {
	ins, err := b.cli.ContainerInspect(parentCtx, cid)
	if err != nil {
		log.Printf("inspect error: %s: %v", cid[:12], err)
		return
	}
	if hasGlobalIgnore(ins.Config.Env, ins.Config.Labels) {
		return
	}

	b.mu.Lock()
	if _, ok := b.reg[cid]; ok {
		b.mu.Unlock()
		return
	}
	b.mu.Unlock()

	ctx, cancel := context.WithCancel(b.rootCtx)
	ip := firstHostIP()

	// Step 1: explicit SERVICE_* env vars
	svcs := parseEnv(ins.Config.Env, ip)

	// Step 2: service.* labels
	if len(svcs) == 0 {
		if s := parseLabels(&ins, ip); s != nil {
			svcs = append(svcs, s)
		}
	}

	// Step 3: fallback → detected ports
	if len(svcs) == 0 {
		svcs = buildDefaultServices(&ins, ip)
	}

	if len(svcs) == 0 {
		cancel()
		return
	}

	containerName := strings.TrimPrefix(ins.Name, "/")

	for _, s := range svcs {
		if s.Name == "" {
			s.Name = containerName
		}
		if strings.HasPrefix(s.ID, "registrator:svc-") {
			s.ID = fmt.Sprintf("registrator:%s:%d", containerName, s.Port)
		}
	}

	b.mu.Lock()
	b.reg[cid] = &regEntry{cancel: cancel}
	b.mu.Unlock()

	for _, s := range svcs {
		validateTTL(s)
		b.wg.Add(1)
		go b.registerRetry(ctx, cid, s)
	}
}

func (b *Bridge) registerRetry(ctx context.Context, cid string, s *Service) {
	defer b.wg.Done()

	backoff := 1 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}

		if err := b.be.Register(s); err == nil {
			if ctx.Err() != nil {
				_ = b.be.Deregister(s)
				return
			}

			b.mu.Lock()
			if entry := b.reg[cid]; entry != nil {
				entry.mu.Lock()
				entry.services = append(entry.services, s)
				entry.mu.Unlock()
			}
			b.mu.Unlock()

			log.Printf("✔ registered %s (%s)", s.ID, cid[:12])

			if s.ttlValid {
				d, _ := time.ParseDuration(s.TTL)
				b.wg.Add(1)
				go b.ttlLoop(ctx, s, maxDuration(d/3, time.Second))
			}
			return
		} else {
			log.Printf("registration failed for %s: %v (retry %s)", cid[:12], err, backoff)
		}

		select {
		case <-time.After(backoff):
			if backoff < 30*time.Second {
				backoff *= 2
			}
		case <-ctx.Done():
			return
		}
	}
}

func (b *Bridge) ttlLoop(ctx context.Context, s *Service, every time.Duration) {
	defer b.wg.Done()

	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := b.be.PassTTL(s); err != nil && debug {
				log.Printf("PassTTL error for %s: %v", s.ID, err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func (b *Bridge) handleStop(cid string) {
	b.mu.Lock()
	entry, ok := b.reg[cid]
	if ok {
		entry.cancel() // stop ttl loops
		delete(b.reg, cid)
	}
	b.mu.Unlock()

	if !ok {
		return
	}

	entry.mu.Lock()
	services := append([]*Service(nil), entry.services...)
	entry.mu.Unlock()

	for _, s := range services {
		// If DeregAfter is set, let Consul remove the service itself.
		if s.DeregAfter != "" {
			if debug {
				log.Printf("⌛ %s: letting Consul deregister after %s", s.ID, s.DeregAfter)
			}
			continue
		}

		for i := 0; i < 3; i++ {
			if err := b.be.Deregister(s); err != nil {
				log.Printf("deregister error (%d/3): %v", i+1, err)
				time.Sleep(time.Second)
				continue
			}
			log.Printf("✖ deregistered %s (%s)", s.ID, cid[:12])
			break
		}
	}
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func firstHostIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}
	for _, iface := range ifaces {
		if iface.Flags&(net.FlagUp|net.FlagLoopback) != net.FlagUp {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.To4() == nil {
				continue
			}
			return ip.String()
		}
	}
	return "127.0.0.1"
}

// buildDefaultServices registers detected ports when no SERVICE_* / labels present.
// If -all-ports flag is false *and* REGISTER_ALL_PORTS env var is absent/false,
// only the first port is registered.
func buildDefaultServices(ins *types.ContainerJSON, ip string) []*Service {
	var res []*Service
	cname := strings.TrimPrefix(ins.Name, "/")

	// envAllPorts becomes true when REGISTER_ALL_PORTS=true|1 is present.
	envAllPorts := false
	for _, e := range ins.Config.Env {
		if strings.HasPrefix(e, "REGISTER_ALL_PORTS=") {
			v := strings.ToLower(strings.TrimPrefix(e, "REGISTER_ALL_PORTS="))
			envAllPorts = v == "true" || v == "1"
			break
		}
	}
	all := *allPorts || envAllPorts

	add := func(port int) {
		res = append(res, &Service{
			ID:   fmt.Sprintf("registrator:%s:%d", cname, port),
			Name: cname,
			Port: port,
			IP:   ip,
		})
	}

	// host network – use container's exposed ports directly
	if ins.HostConfig.NetworkMode == "host" {
		for p := range ins.Config.ExposedPorts {
			add(int(p.Int()))
			if !all {
				break
			}
		}
		return res
	}

	// bridge / user networks – prefer published host ports
	if len(ins.NetworkSettings.Ports) > 0 {
		for _, binds := range ins.NetworkSettings.Ports {
			if len(binds) == 0 {
				continue
			}
			hostPort, _ := strconv.Atoi(binds[0].HostPort)
			add(hostPort)
			if !all {
				return res
			}
		}
	} else { // fallback: exposed ports
		for p := range ins.Config.ExposedPorts {
			add(int(p.Int()))
			if !all {
				break
			}
		}
	}
	return res
}

// parseEnv converts SERVICE_* env vars into Service instances.
func parseEnv(env []string, ip string) []*Service {
	svcMap := map[string]*Service{}

	for _, e := range env {
		if !strings.HasPrefix(e, "SERVICE_") {
			continue
		}
		kv := strings.SplitN(e, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key, val := kv[0], kv[1]
		parts := strings.Split(key, "_")
		if len(parts) < 3 {
			continue
		}
		portStr := parts[1]
		if _, err := strconv.Atoi(portStr); err != nil {
			continue
		}
		field := strings.Join(parts[2:], "_")
		if strings.HasPrefix(field, "CHECK_") {
			field = strings.TrimPrefix(field, "CHECK_")
		}

		// IGNORE=true|1 => drop the port entirely
		if field == "IGNORE" && (strings.ToLower(val) == "true" || val == "1") {
			delete(svcMap, portStr)
			continue
		}

		svc := svcMap[portStr]
		if svc == nil {
			p, _ := strconv.Atoi(portStr)
			svc = &Service{
				ID:   fmt.Sprintf("registrator:svc-%s", portStr),
				Port: p,
				IP:   ip,
			}
			svcMap[portStr] = svc
		}

		switch field {
		case "NAME":
			svc.Name = val
		case "ID":
			svc.ID = val
		case "TAGS":
			svc.Tags = strings.Split(val, ",")
		case "HTTP", "PATH":
			svc.HTTPPath = val
		case "TCP":
			svc.TCPCheck = strings.ToLower(val) == "true"
		case "TTL":
			svc.TTL = val
		case "INTERVAL":
			svc.Interval = val
		case "TIMEOUT":
			svc.Timeout = val
		case "DEREG_AFTER", "DEREG":
			svc.DeregAfter = val
		}
	}

	var res []*Service
	for _, s := range svcMap {
		res = append(res, s)
	}
	return res
}

func parseLabels(ins *types.ContainerJSON, ip string) *Service {
	lbl := ins.Config.Labels
	portStr := lbl["service.port"]
	if portStr == "" {
		return nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil
	}

	// per-port ignore
	ignoreKey := fmt.Sprintf("service.%s.ignore", portStr)
	if v := strings.ToLower(lbl[ignoreKey]); v == "true" || v == "1" {
		return nil
	}

	cname := strings.TrimPrefix(ins.Name, "/")

	s := &Service{
		ID:   firstNonEmpty(lbl["service.id"], fmt.Sprintf("registrator:%s:%d", cname, port)),
		Name: firstNonEmpty(lbl["service.name"], cname),
		Port: port,
		IP:   ip,
	}
	if tags := lbl["service.tags"]; tags != "" {
		s.Tags = strings.Split(tags, ",")
	}
	s.HTTPPath = firstNonEmpty(lbl["service.check_http"], lbl["service.http"])
	s.Interval = firstNonEmpty(lbl["service.check_interval"], lbl["service.interval"])
	s.Timeout = firstNonEmpty(lbl["service.check_timeout"], lbl["service.timeout"])
	s.TTL = firstNonEmpty(lbl["service.check_ttl"], lbl["service.ttl"])
	s.DeregAfter = firstNonEmpty(lbl["service.dereg_after"], lbl["service.dereg"])
	if tcp := lbl["service.tcp"]; tcp == "true" {
		s.TCPCheck = true
	}
	return s
}

func validateTTL(s *Service) {
	if s.TTL == "" {
		return
	}
	ttlDur, err := time.ParseDuration(s.TTL)
	if err != nil || ttlDur <= 0 {
		log.Printf("invalid TTL for %s — ignored", s.ID)
		s.TTL = ""
		s.DeregAfter = ""
		return
	}

	if s.DeregAfter != "" {
		deregDur, err := time.ParseDuration(s.DeregAfter)
		if err != nil || deregDur <= ttlDur {
			s.DeregAfter = (ttlDur * 2).String()
			log.Printf("DeregisterAfter corrected for %s to %s", s.ID, s.DeregAfter)
		}
	} else {
		s.DeregAfter = (ttlDur * 2).String()
		log.Printf("DeregisterAfter set for %s to %s", s.ID, s.DeregAfter)
	}
	s.ttlValid = true
}

// ----------------------------------------------------------------------
// main
// ----------------------------------------------------------------------

func main() {
	insecure := flag.Bool("insecure", os.Getenv("CONSUL_SKIP_VERIFY") == "1", "Skip TLS certificate verification")
	consulAddr := flag.String("consul", os.Getenv("CONSUL_ADDR"), "Consul address, e.g. https://consul:8500")
	flag.Parse()

	be := newConsulBackend(*consulAddr, *insecure)
	br, err := newBridge(be)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := br.Close(); err != nil {
			log.Printf("error closing Docker client: %v", err)
		}
	}()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := br.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}
