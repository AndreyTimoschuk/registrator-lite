package main

import (
    "bytes"
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "os"
    "strconv"
    "strings"
    "sync"
    "time"

    "github.com/docker/docker/api/types"
    "github.com/docker/docker/api/types/container"
    "github.com/docker/docker/api/types/events"
    "github.com/docker/docker/api/types/filters"
    "github.com/docker/docker/client"
)

var debug = os.Getenv("DEBUG") == "1"

// Service describes a Consul service
// -----------------------------------------------------------------------------
type Service struct {
    ID, Name        string
    IP              string
    Port            int
    Tags            []string
    HTTPPath        string
    TCP             bool
    TTL             string
    Interval        string
    Timeout         string
    DeregAfter      string
    ttlValid        bool
}

// Backend manages Consul registration
// -----------------------------------------------------------------------------
type Backend interface {
    Register(*Service) error
    Deregister(*Service) error
    PassTTL(*Service) error
}

type consulBackend struct {
    addr   string
    client *http.Client
}

func newConsulBackend(addr string) *consulBackend {
    if addr == "" {
        addr = "consul:8500"
    }
    if !strings.HasPrefix(addr, "http") {
        addr = "http://" + addr
    }
    return &consulBackend{addr: addr, client: &http.Client{Timeout: 5 * time.Second}}
}

func (c *consulBackend) put(path string, payload any) error {
    var buf bytes.Buffer
    if payload != nil {
        if err := json.NewEncoder(&buf).Encode(payload); err != nil {
            return err
        }
    }
    if debug {
        log.Printf("→ PUT %s%s (%d bytes)", c.addr, path, buf.Len())
    }
    req, _ := http.NewRequest(http.MethodPut, c.addr+path, &buf)
    req.Header.Set("Content-Type", "application/json")
    resp, err := c.client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    if resp.StatusCode >= 300 {
        msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
        return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(msg)))
    }
    return nil
}

func (c *consulBackend) buildCheck(s *Service) map[string]string {
    base := firstNonEmpty(s.DeregAfter, "1m")
    switch {
    case s.ttlValid:
        return map[string]string{"TTL": s.TTL, "DeregisterCriticalServiceAfter": base}
    case s.HTTPPath != "":
        return map[string]string{
            "HTTP": fmt.Sprintf("http://%s:%d%s", s.IP, s.Port, s.HTTPPath),
            "Interval": firstNonEmpty(s.Interval, "10s"),
            "Timeout": firstNonEmpty(s.Timeout, "2s"),
            "DeregisterCriticalServiceAfter": base,
        }
    case s.TCP:
        return map[string]string{
            "TCP": fmt.Sprintf("%s:%d", s.IP, s.Port),
            "Interval": firstNonEmpty(s.Interval, "10s"),
            "Timeout": firstNonEmpty(s.Timeout, "2s"),
            "DeregisterCriticalServiceAfter": base,
        }
    default:
        return nil
    }
}

func (c *consulBackend) Register(s *Service) error {
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
    return c.put("/v1/agent/service/register", payload)
}

func (c *consulBackend) Deregister(s *Service) error {
    return c.put("/v1/agent/service/deregister/"+s.ID, nil)
}

func (c *consulBackend) PassTTL(s *Service) error {
    if !s.ttlValid {
        return nil
    }
    return c.put("/v1/agent/check/pass/service:"+s.ID, nil)
}

// Bridge wires Docker events to Consul backend
// -----------------------------------------------------------------------------
type Bridge struct {
    cli *client.Client
    be  Backend
    mu  sync.Mutex
    reg map[string][]*Service
}

func newBridge(be Backend) (*Bridge, error) {
    cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
    if err != nil {
        return nil, err
    }
    return &Bridge{cli: cli, be: be, reg: make(map[string][]*Service)}, nil
}

func (b *Bridge) Run(ctx context.Context) error {
    // initial scan
    list, _ := b.cli.ContainerList(ctx, container.ListOptions{})
    for _, c := range list {
        b.handleStart(ctx, c.ID)
    }
    // subscribe to events
    f := filters.NewArgs()
    f.Add("type", "container")
    f.Add("event", "start")
    f.Add("event", "die")
    f.Add("event", "destroy")
    msgs, errs := b.cli.Events(ctx, events.ListOptions{Filters: f})
    for {
        select {
        case m := <-msgs:
            if m.Action == "start" {
                go b.handleStart(ctx, m.ID)
            } else {
                go b.handleStop(m.ID)
            }
        case err := <-errs:
            return err
        case <-ctx.Done():
            return ctx.Err()
        }
    }
}

func hasGlobalIgnore(env []string, labels map[string]string) bool {
    for _, e := range env {
        if e == "SERVICE_IGNORE=true" {
            return true
        }
    }
    if labels["SERVICE_IGNORE"] == "true" {
        return true
    }
    return false
}

func (b *Bridge) handleStart(ctx context.Context, cid string) {
    ins, err := b.cli.ContainerInspect(ctx, cid)
    if err != nil {
        log.Println("inspect error:", err)
        return
    }
    if hasGlobalIgnore(ins.Config.Env, ins.Config.Labels) {
        return
    }
    ip := firstHostIP()
    // 1) ENV-style multi-port
    svcs := parseEnv(ins.Config.Env, ip)
    // 2) labels fallback single-port
    if len(svcs) == 0 {
        if s := parseLabels(&ins, ip); s != nil {
            svcs = append(svcs, s)
        }
    }
    // 3) container_name fallback when no NAME
    for _, s := range svcs {
        if strings.HasPrefix(s.ID, "registrator:svc-") {
            name := strings.TrimPrefix(ins.Name, "/")
            s.Name = name
            s.ID = fmt.Sprintf("registrator:%s:%d", name, s.Port)
        }
    }
    // register each
    for _, s := range svcs {
        validateTTL(s)
        go b.registerRetry(ctx, cid, s)
    }
}

func (b *Bridge) registerRetry(ctx context.Context, cid string, s *Service) {
    backoff := 2 * time.Second
    for {
        if err := b.be.Register(s); err == nil {
            b.mu.Lock()
            b.reg[cid] = append(b.reg[cid], s)
            b.mu.Unlock()
            log.Printf("✔ registered %s (%s)", s.ID, cid[:12])
            if s.ttlValid {
                d, _ := time.ParseDuration(s.TTL)
                go b.ttlLoop(ctx, s, d/2)
            }
            return
        } else {
            log.Printf("registration failed for %s: %v (retry %s)", cid[:12], err, backoff)
        }
        select {
        case <-time.After(backoff):
            if backoff < time.Minute {
                backoff *= 2
            }
        case <-ctx.Done():
            return
        }
    }
}

func (b *Bridge) ttlLoop(ctx context.Context, s *Service, every time.Duration) {
    if every < 5*time.Second {
        every = 5 * time.Second
    }
    ticker := time.NewTicker(every)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            _ = b.be.PassTTL(s)
        case <-ctx.Done():
            return
        }
    }
}

func (b *Bridge) handleStop(cid string) {
    b.mu.Lock()
    services := b.reg[cid]
    delete(b.reg, cid)
    b.mu.Unlock()
    for _, s := range services {
        if err := b.be.Deregister(s); err != nil {
            log.Println("deregister error:", err)
        } else {
            log.Printf("✖ deregistered %s (%s)", s.ID, cid[:12])
        }
    }
}

// get first exposed TCP port from image (host-network fallback)
func getExposedPort(ins *types.ContainerJSON) int {
    for ep := range ins.Config.ExposedPorts {
        if p, err := strconv.Atoi(strings.Split(string(ep), "/")[0]); err == nil {
            return p
        }
    }
    return 0
}

// parseEnv: SERVICE_<PORT>_* parsing with port-level IGNORE
func parseEnv(env []string, ip string) []*Service {
    ports := map[string]map[string]string{}
    for _, e := range env {
        if !strings.HasPrefix(e, "SERVICE_") {
            continue
        }
        kv := strings.SplitN(e[len("SERVICE_"):], "=", 2)
        if len(kv) != 2 {
            continue
        }
        parts := strings.SplitN(kv[0], "_", 2)
        if len(parts) != 2 {
            continue
        }
        p, f := parts[0], parts[1]
        if _, ok := ports[p]; !ok {
            ports[p] = map[string]string{}
        }
        ports[p][f] = kv[1]
    }
    var res []*Service
    for p, m := range ports {
        if m["IGNORE"] == "true" {
            continue
        }
        port, err := strconv.Atoi(p)
        if err != nil || port == 0 {
            continue
        }
        name := firstNonEmpty(m["NAME"], "svc-"+p)
        id := firstNonEmpty(m["ID"], fmt.Sprintf("registrator:%s:%s", name, p))
        s := &Service{
            ID:        id,
            Name:      name,
            IP:        ip,
            Port:      port,
            Tags:      splitCSV(m["TAGS"]),
            HTTPPath:  m["CHECK_HTTP"],
            TCP:       m["TCP"] == "true",
            TTL:       m["TTL"],
            Interval:  m["CHECK_INTERVAL"],
            Timeout:   m["CHECK_TIMEOUT"],
            DeregAfter: m["DEREG_AFTER"],
        }
        res = append(res, s)
    }
    return res
}

// parseLabels: single-port via labels with port-level and global IGNORE
func parseLabels(ins *types.ContainerJSON, ip string) *Service {
    l := ins.Config.Labels
    if l["SERVICE_IGNORE"] == "true" {
        return nil
    }
    port := 0
    if p := l["SERVICE_PORT"]; p != "" {
        port, _ = strconv.Atoi(p)
    }
    if port == 0 {
        for _, b := range ins.NetworkSettings.Ports {
            if len(b) > 0 {
                port, _ = strconv.Atoi(b[0].HostPort)
                if port != 0 {
                    break
                }
            }
        }
    }
    if port == 0 {
        port = getExposedPort(ins)
    }
    if port == 0 || l[fmt.Sprintf("SERVICE_%d_IGNORE", port)] == "true" {
        return nil
    }
    name := firstNonEmpty(l["SERVICE_NAME"], strings.TrimPrefix(ins.Name, "/"))
    id := firstNonEmpty(l["SERVICE_ID"], fmt.Sprintf("registrator:%s:%d", name, port))
    return &Service{ID: id, Name: name, IP: ip, Port: port,
        Tags: splitCSV(l["SERVICE_TAGS"]),
        HTTPPath: l["SERVICE_CHECK_HTTP"],
        TCP:       l["SERVICE_TCP"] == "true",
        TTL:       l["SERVICE_TTL"],
        Interval:  l["SERVICE_CHECK_INTERVAL"],
        Timeout:   l["SERVICE_CHECK_TIMEOUT"],
        DeregAfter: l["SERVICE_DEREG_AFTER"],
    }
}

// validateTTL sets ttlValid if TTL>0
func validateTTL(s *Service) {
    if s.TTL == "" {
        return
    }
    if d, err := time.ParseDuration(s.TTL); err == nil && d > 0 {
        s.ttlValid = true
    } else {
        log.Printf("invalid TTL for %s — ignored", s.ID)
        s.TTL = ""
    }
}

func splitCSV(s string) []string {
    if s == "" {
        return nil
    }
    parts := strings.Split(s, ",")
    var out []string
    for _, p := range parts {
        if t := strings.TrimSpace(p); t != "" {
            out = append(out, t)
        }
    }
    return out
}

func firstNonEmpty(a, b string) string {
    if a != "" {
        return a
    }
    return b
}

func firstHostIP() string {
    if env := os.Getenv("HOST_IP"); env != "" {
        return env
    }
    ifaces, _ := net.Interfaces()
    for _, iface := range ifaces {
        if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
            continue
        }
        addrs, _ := iface.Addrs()
        for _, a := range addrs {
            if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
                return ipn.IP.String()
            }
        }
    }
    return "127.0.0.1"
}

func main() {
    be := newConsulBackend(os.Getenv("CONSUL_ADDR"))
    br, err := newBridge(be)
    if err != nil {
        log.Fatal(err)
    }
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    if err := br.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
        log.Fatal(err)
    }
}
