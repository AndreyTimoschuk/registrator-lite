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

// ------------------------ Constants ------------------------
// These prefixes are used as tags in Consul.
const (
    mgrTagPrefix  = "managed-by=registrator-lite" // shows who manages the service
    nodeTagPrefix = "node:"                      // shows Docker node name
    cidTagPrefix  = "cid:"                       // shows container id prefix
)

// ------------------------ Global flags --------------------
// Flags can be set with command line or ENV vars.
var (
    debug       = envBool("DEBUG", false)                                   // show debug logs
    allPorts    = flag.Bool("all-ports", envBool("ALL_PORTS", false), "register every port")
    cleanup     = flag.Bool("cleanup", envBool("CLEANUP", false), "remove stale services")
    internal    = flag.Bool("internal", envBool("INTERNAL", false), "use container IPs")
    resync      = flag.Duration("resync", envDuration("RESYNC", 60*time.Second), "resync interval (0 disables)")
    defTTL      = flag.Duration("ttl", envDuration("TTL", 0), "default TTL for services (0 disables)")
    insecure    = flag.Bool("insecure", envBool("CONSUL_SKIP_VERIFY", false), "skip TLS verify")
    autoTags    = flag.Bool("auto-tags", envBool("AUTO_TAGS", true), "attach managed-by/node/cid tags")
    consulAddr  = flag.String("consul", os.Getenv("CONSUL_ADDR"), "Consul address")
    consulToken = os.Getenv("CONSUL_HTTP_TOKEN") // token for ACL
)

// init is called first. Seed random numbers.
func init() { rand.Seed(time.Now().UnixNano()) }

// ------------------------ Helpers -------------------------
// parseBool reads a string and returns true/false.
func parseBool(s string, def bool) bool {
    s = strings.ToLower(strings.TrimSpace(s))
    switch s {
    case "1", "true", "yes":
        return true
    case "0", "false", "no":
        return false
    }
    return def
}

// envBool gets a bool from ENV. If not set, it returns default.
func envBool(k string, d bool) bool { return parseBool(os.Getenv(k), d) }

// envDuration gets a time.Duration from ENV.
func envDuration(k string, d time.Duration) time.Duration {
    if v := os.Getenv(k); v != "" {
        if x, err := time.ParseDuration(v); err == nil {
            return x
        }
        log.Printf("invalid duration for %s: %q", k, v)
    }
    return d
}

// firstNonEmpty returns the first non empty string.
func firstNonEmpty(a, b string) string { if a != "" { return a }; return b }

// maxDuration returns the bigger duration.
func maxDuration(a, b time.Duration) time.Duration {
    if a > b {
        return a
    }
    return b
}

// hasAllPortsEnv checks env for ALL_PORTS setting.
func hasAllPortsEnv(env []string) bool {
    for _, e := range env {
        if strings.HasPrefix(e, "REGISTER_ALL_PORTS=") ||
            strings.HasPrefix(e, "ALL_PORTS=") {
            return parseBool(strings.SplitN(e, "=", 2)[1], false)
        }
    }
    return false
}

// svcAutoTags returns per-container AUTO_TAGS override.
func svcAutoTags(env []string) *bool {
    for _, e := range env {
        if strings.HasPrefix(e, "SERVICE_AUTO_TAGS=") {
            v := parseBool(strings.SplitN(e, "=", 2)[1], true)
            return &v
        }
    }
    return nil
}

// appendUnique adds tags without duplicates.
func appendUnique(sl []string, vv ...string) []string {
outer:
    for _, v := range vv {
        for _, e := range sl {
            if e == v {
                continue outer
            }
        }
        sl = append(sl, v)
    }
    return sl
}

// ------------------- HOST_IP override --------------------
// envHostIP returns HOST_IP env or firstHostIP() fallback.
func envHostIP() string {
    if h := strings.TrimSpace(os.Getenv("HOST_IP")); h != "" {
        return h
    }
    return firstHostIP()
}

// ----------------------- Service --------------------------
// Service holds data that will be sent to Consul.
// Note: only public fields are exported to JSON.
type Service struct {
    ID, Name   string   // IDs and names in Consul
    IP         string   // service IP
    Port       int      // service port
    Tags       []string // list of tags
    HTTPPath   string   // HTTP health path
    TCPCheck   bool     // use TCP check
    TTL        string   // TTL value as string
    Interval   string   // check interval
    Timeout    string   // check timeout
    DeregAfter string   // deregister time
    ttlValid   bool     // internal flag
    SkipCheck  bool     // do not add health check
}

// validateTTL sets ttlValid if TTL is correct.
func validateTTL(s *Service) {
    if s.TTL == "" {
        s.ttlValid = false
        return
    }
    d, err := time.ParseDuration(s.TTL)
    if err != nil || d <= 0 {
        log.Printf("invalid TTL for %s: %v", s.ID, err)
        s.ttlValid = false
        return
    }
    s.ttlValid = true
}

// ------------------- Consul backend ----------------------
// Backend interface hides Consul details.
// We can mock it in tests.

type Backend interface {
    Register(*Service) error
    Deregister(*Service) error
    PassTTL(*Service) error
    List() (map[string]json.RawMessage, error)
}

// consulBackend talks to Consul HTTP API.
type consulBackend struct {
    addr, scheme string
    client       *http.Client
    token        string
}

// newConsulBackend creates a Consul client.
func newConsulBackend(addr string, insecure bool, token string) *consulBackend {
    if addr == "" {
        addr = "localhost:8500"
    }
    addr = strings.TrimPrefix(strings.TrimPrefix(addr, "http://"), "https://")
    addr = strings.TrimSuffix(addr, "/")
    scheme := "http://"
    if strings.HasPrefix(os.Getenv("CONSUL_ADDR"), "https://") {
        scheme = "https://"
    }
    tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}}
    return &consulBackend{
        addr:   addr,
        scheme: scheme,
        token:  token,
        client: &http.Client{
            Timeout:       10 * time.Second,
            Transport:     tr,
            CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
        },
    }
}

// do sends an HTTP request to Consul.
func (c *consulBackend) do(ctx context.Context, method, path string, body io.Reader) error {
    req, err := http.NewRequestWithContext(ctx, method, c.scheme+c.addr+path, body)
    if err != nil {
        return err
    }
    if body != nil {
        req.Header.Set("Content-Type", "application/json")
    }
    if c.token != "" {
        req.Header.Set("X-Consul-Token", c.token)
    }
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

// put is a helper for PUT requests with JSON body.
func (c *consulBackend) put(ctx context.Context, path string, payload any) error {
    var body io.Reader
    if payload != nil {
        b, _ := json.Marshal(payload)
        body = bytes.NewReader(b)
    }
    return c.do(ctx, http.MethodPut, path, body)
}

// Register adds a service to Consul.
func (c *consulBackend) Register(s *Service) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    pl := map[string]any{"ID": s.ID, "Name": s.Name, "Address": s.IP, "Port": s.Port, "Tags": s.Tags}
    if chk := c.buildCheck(s); chk != nil {
        pl["Check"] = chk
    }
    return c.put(ctx, "/v1/agent/service/register", pl)
}

// Deregister removes a service from Consul.
func (c *consulBackend) Deregister(s *Service) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    return c.do(ctx, http.MethodPut, "/v1/agent/service/deregister/"+url.PathEscape(s.ID), nil)
}

// PassTTL marks TTL check as OK.
func (c *consulBackend) PassTTL(s *Service) error {
    if !s.ttlValid || s.SkipCheck {
        return nil
    }
    ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
    defer cancel()
    return c.do(ctx, http.MethodPut, "/v1/agent/check/pass/service:"+url.PathEscape(s.ID), nil)
}

// List gets all local services from Consul.
func (c *consulBackend) List() (map[string]json.RawMessage, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.scheme+c.addr+"/v1/agent/services", nil)
    if c.token != "" {
        req.Header.Set("X-Consul-Token", c.token)
    }
    resp, err := c.client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    var out map[string]json.RawMessage
    if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
        return nil, err
    }
    return out, nil
}

// buildCheck creates the health check JSON.
func (c *consulBackend) buildCheck(s *Service) map[string]any {
    if s.SkipCheck {
        return nil
    }
    dereg := firstNonEmpty(s.DeregAfter, "1m")
    switch {
    case s.ttlValid:
        return map[string]any{"TTL": s.TTL, "DeregisterCriticalServiceAfter": dereg}
    case s.HTTPPath != "":
        target := s.HTTPPath
        if !strings.HasPrefix(target, "http") {
            if !strings.HasPrefix(target, "/") {
                target = "/" + target
            }
            target = fmt.Sprintf("http://%s:%d%s", s.IP, s.Port, target)
        }
        return map[string]any{
            "HTTP": target, "Interval": firstNonEmpty(s.Interval, "10s"),
            "Timeout": firstNonEmpty(s.Timeout, "2s"),
            "DeregisterCriticalServiceAfter": dereg,
        }
    case s.TCPCheck:
        return map[string]any{
            "TCP": fmt.Sprintf("%s:%d", s.IP, s.Port),
            "Interval": firstNonEmpty(s.Interval, "10s"),
            "Timeout": firstNonEmpty(s.Timeout, "2s"),
            "DeregisterCriticalServiceAfter": dereg,
        }
    }
    return nil
}

// ---------------- Docker bridge (watcher) -----------------
type regEntry struct {
    services []*Service       // registered services
    cancel   context.CancelFunc // to stop goroutines
    mu       sync.Mutex
}

type Bridge struct {
    cli     *client.Client
    be      Backend
    mu      sync.Mutex
    reg     map[string]*regEntry // key: container id
    wg      sync.WaitGroup
    rootCtx context.Context
    host    string // host name
}

// newBridge builds a Bridge.
func newBridge(be Backend) (*Bridge, error) {
    cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
    if err != nil {
        return nil, err
    }
    hn, _ := os.Hostname()
    return &Bridge{cli: cli, be: be, reg: make(map[string]*regEntry), host: hn}, nil
}

// Close closes Docker client.
func (b *Bridge) Close() error { return b.cli.Close() }

// Run starts listening to Docker events.
func (b *Bridge) Run(ctx context.Context) error {
    b.rootCtx = ctx
    f := filters.NewArgs()
    f.Add("type", "container")
    for _, ev := range []string{"start", "die", "destroy", "stop", "kill"} {
        f.Add("event", ev)
    }
    msgs, errs := b.cli.Events(ctx, events.ListOptions{Filters: f})

    var ticker *time.Ticker
    if *resync > 0 {
        ticker = time.NewTicker(*resync)
        defer ticker.Stop()
    }
    if err := b.initialScan(ctx, *cleanup); err != nil {
        return err
    }

    for {
        select {
        case m := <-msgs: // handle Docker event
            switch m.Action {
            case "start":
                go b.handleStart(ctx, m.ID)
            case "die", "destroy", "stop", "kill":
                go b.handleStop(m.ID)
            }
        case err := <-errs:
            return err
        case <-ticker.C:
            _ = b.initialScan(ctx, *cleanup)
        case <-ctx.Done():
            b.wg.Wait()
            return ctx.Err()
        }
    }
}

// initialScan registers running containers on start.
func (b *Bridge) initialScan(ctx context.Context, doCleanup bool) error {
    list, err := b.cli.ContainerList(ctx, container.ListOptions{})
    if err != nil {
        return err
    }
    running := map[string]struct{}{}
    for _, c := range list {
        running[c.ID] = struct{}{}
        b.mu.Lock()
        _, exists := b.reg[c.ID]
        b.mu.Unlock()
        if !exists {
            go b.handleStart(ctx, c.ID)
        }
    }
    if doCleanup {
        b.cleanupConsul(ctx, running)
    }
    return nil
}

// cleanupConsul removes stale services.
func (b *Bridge) cleanupConsul(ctx context.Context, running map[string]struct{}) {
    srvs, err := b.be.List()
    if err != nil {
        log.Printf("cleanup: list error: %v", err)
        return
    }
    aliveCID := map[string]struct{}{}
    for cid := range running {
        aliveCID[cid[:12]] = struct{}{}
    }

    for id, raw := range srvs {
        var svc struct {
            Tags []string `json:"Tags"`
        }
        if err := json.Unmarshal(raw, &svc); err != nil {
            continue
        }
        if !contains(svc.Tags, mgrTagPrefix) || !contains(svc.Tags, nodeTagPrefix+b.host) {
            continue // not our manager or not our node
        }
        cidTag := findTagPrefix(svc.Tags, cidTagPrefix)
        if cidTag == "" {
            continue
        }
        if _, alive := aliveCID[cidTag]; alive {
            continue // container still running
        }
        if err := b.be.Deregister(&Service{ID: id}); err == nil {
            log.Printf("cleanup: ✖ stale %s", id)
        }
    }
}

// contains checks if slice has value.
func contains(sl []string, v string) bool {
    for _, e := range sl {
        if e == v {
            return true
        }
    }
    return false
}

// findTagPrefix finds first tag with prefix.
func findTagPrefix(sl []string, pfx string) string {
    for _, t := range sl {
        if strings.HasPrefix(t, pfx) {
            return strings.TrimPrefix(t, pfx)
        }
    }
    return ""
}

// ---------------- start / stop logic ----------------------
// handleStart registers services for a new container.
func (b *Bridge) handleStart(ctx context.Context, cid string) {
    ins, err := b.cli.ContainerInspect(ctx, cid)
    if err != nil {
        log.Printf("inspect %s: %v", cid[:12], err)
        return
    }
    if hasGlobalIgnore(ins.Config.Env, ins.Config.Labels) {
        return
    }

    containerInternal := *internal || hasInternalEnv(ins.Config.Env, ins.Config.Labels)
    ip := envHostIP()
    if containerInternal {
        ip = containerIP(&ins)
    }

    svcs := parseEnv(ins.Config.Env, ip)
    if len(svcs) == 0 {
        if s := parseLabels(&ins, ip); s != nil {
            svcs = append(svcs, s)
        }
    }
    if len(svcs) == 0 {
        svcs = buildDefaultServices(&ins, ip)
    }
    if len(svcs) == 0 {
        return
    }

    containerName := composeServiceName(&ins)
    for _, s := range svcs {
        if s.Name == "" {
            s.Name = containerName
        }
        if s.ID == "" {
            s.ID = fmt.Sprintf("registrator:%s:%d", s.Name, s.Port)
        }

        // add special tags
        addTags := *autoTags
        if v := svcAutoTags(ins.Config.Env); v != nil {
            addTags = *v
        }
        if addTags {
            s.Tags = appendUnique(s.Tags,
                mgrTagPrefix,
                nodeTagPrefix+b.host,
                cidTagPrefix+cid[:12],
            )
        }

        if containerInternal {
            s.SkipCheck = true
            s.HTTPPath, s.TCPCheck, s.TTL = "", false, ""
        }
        if !s.SkipCheck && s.TTL == "" && *defTTL > 0 {
            s.TTL = defTTL.String()
        }
        validateTTL(s)
    }

    ctx2, cancel := context.WithCancel(b.rootCtx)
    b.mu.Lock()
    b.reg[cid] = &regEntry{cancel: cancel}
    b.mu.Unlock()

    for _, s := range svcs {
        b.wg.Add(1)
        go b.registerRetry(ctx2, cid, s)
    }
}

// registerRetry tries to register until success or context end.
func (b *Bridge) registerRetry(ctx context.Context, cid string, s *Service) {
    defer b.wg.Done()
    back := time.Second
    for {
        if ctx.Err() != nil {
            return
        }
        if err := b.be.Register(s); err == nil {
            b.mu.Lock()
            if e := b.reg[cid]; e != nil {
                e.mu.Lock()
                e.services = append(e.services, s)
                e.mu.Unlock()
            }
            b.mu.Unlock()
            log.Printf("✔ registered %s (%s)", s.ID, cid[:12])

            if s.ttlValid && !s.SkipCheck {
                d, _ := time.ParseDuration(s.TTL)
                b.wg.Add(1)
                go b.ttlLoop(ctx, s, maxDuration(d/3, time.Second))
            }
            return
        }
        time.Sleep(back)
        if back < 30*time.Second {
            back *= 2
        }
    }
}

// ttlLoop sends TTL check passes.
func (b *Bridge) ttlLoop(ctx context.Context, s *Service, every time.Duration) {
    tk := time.NewTicker(every)
    defer func() { tk.Stop(); b.wg.Done() }()
    for {
        select {
        case <-tk.C:
            _ = b.be.PassTTL(s)
        case <-ctx.Done():
            return
        }
    }
}

// handleStop deregisters when container stops.
func (b *Bridge) handleStop(cid string) {
    b.mu.Lock()
    entry, ok := b.reg[cid]
    if ok {
        entry.cancel()
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
        if s.DeregAfter != "" {
            continue
        }
        for i := 0; i < 3; i++ {
            if err := b.be.Deregister(s); err == nil {
                log.Printf("✖ deregistered %s (%s)", s.ID, cid[:12])
                break
            }
            time.Sleep(time.Second)
        }
    }
}

// ------------- ENV / LABEL parsing helpers ---------------
// parseEnv reads SERVICE_* env vars and makes Service objects.
func parseEnv(env []string, ip string) []*Service {
    by := map[int]*Service{}
    ignored := map[int]bool{} // ports with IGNORE=true

    for _, e := range env {
        if !strings.HasPrefix(e, "SERVICE_") {
            continue
        }
        kv := strings.SplitN(e, "=", 2)
        if len(kv) != 2 {
            continue
        }
        key, val := strings.TrimPrefix(kv[0], "SERVICE_"), kv[1]

        // old format SERVICE_PORT
        if key == "PORT" {
            if p, err := strconv.Atoi(val); err == nil && p > 0 {
                by[p] = &Service{IP: ip, Port: p}
            }
            continue
        }

        ps := strings.SplitN(key, "_", 2)
        if len(ps) != 2 {
            continue
        }
        port, err := strconv.Atoi(ps[0])
        if err != nil || port <= 0 {
            continue
        }
        field := ps[1]

        // if port is ignored, skip other fields
        if ignored[port] && field != "IGNORE" {
            continue
        }

        // IGNORE field
        if field == "IGNORE" {
            if parseBool(val, false) {
                ignored[port] = true
                delete(by, port)
            }
            continue
        }

        svc := by[port]
        if svc == nil {
            svc = &Service{IP: ip, Port: port}
            by[port] = svc
        }

        switch field {
        case "NAME":
            svc.Name = val
        case "ID":
            svc.ID = val
        case "TAGS":
            svc.Tags = strings.Split(strings.Trim(val, ","), ",")
        case "TCP":
            svc.TCPCheck = parseBool(val, false)
        case "TTL":
            svc.TTL = val
        case "CHECK_HTTP":
            svc.HTTPPath = val
        case "CHECK_INTERVAL":
            svc.Interval = val
        case "CHECK_TIMEOUT":
            svc.Timeout = val
        case "DEREG_AFTER":
            svc.DeregAfter = val
        }
    }

    out := make([]*Service, 0, len(by))
    for p, s := range by {
        if !ignored[p] && s != nil {
            out = append(out, s)
        }
    }
    return out
}

// parseLabels extracts Service from Docker labels.
func parseLabels(ins *types.ContainerJSON, ip string) *Service {
    lbl := ins.Config.Labels
    name := lbl["service.name"]
    port, _ := strconv.Atoi(lbl["service.port"])
    if name == "" || port == 0 {
        return nil
    }
    return &Service{
        ID:   fmt.Sprintf("registrator:%s:%d", name, port),
        Name: name,
        IP:   ip,
        Port: port,
        Tags: strings.Split(strings.Trim(lbl["service.tags"], ","), ","),
    }
}

// buildDefaultServices uses ExposedPorts when no SERVICE_ vars.
func buildDefaultServices(ins *types.ContainerJSON, ip string) []*Service {
    useAll := *allPorts || hasAllPortsEnv(ins.Config.Env)

    // collect ports with IGNORE=true
    ignored := map[int]bool{}
    for _, e := range ins.Config.Env {
        if !strings.HasPrefix(e, "SERVICE_") {
            continue
        }
        kv := strings.SplitN(e, "=", 2)
        if len(kv) != 2 {
            continue
        }
        key, val := strings.TrimPrefix(kv[0], "SERVICE_"), kv[1]
        ps := strings.SplitN(key, "_", 2)
        if len(ps) != 2 {
            continue
        }
        p, err := strconv.Atoi(ps[0])
        if err != nil || p <= 0 {
            continue
        }
        if ps[1] == "IGNORE" && parseBool(val, false) {
            ignored[p] = true
        }
    }

    var out []*Service

    if len(ins.NetworkSettings.Ports) == 0 {
        for p := range ins.Config.ExposedPorts {
            port, _ := strconv.Atoi(strings.Split(string(p), "/")[0])
            if port == 0 || ignored[port] {
                continue
            }
            out = append(out, &Service{IP: ip, Port: port})
            if !useAll {
                break
            }
        }
        return out
    }

    for proto, binds := range ins.NetworkSettings.Ports {
        port, _ := strconv.Atoi(strings.Split(string(proto), "/")[0])
        if port == 0 || ignored[port] {
            continue
        }
        if len(binds) == 0 {
            out = append(out, &Service{IP: ip, Port: port})
            if !useAll {
                break
            }
            continue
        }
        for _, b := range binds {
            p, _ := strconv.Atoi(b.HostPort)
            if p == 0 || ignored[p] {
                continue
            }
            out = append(out, &Service{IP: ip, Port: p})
            if !useAll {
                break
            }
        }
        if !useAll && len(out) > 0 {
            break
        }
    }
    return out
}

// ------------ compose service name (FIX) ---------------
// composeServiceName picks a readable name for Consul.
func composeServiceName(ins *types.ContainerJSON) string {
    // take name from docker-compose label
    if svc := ins.Config.Labels["com.docker.compose.service"]; svc != "" {
        cname := strings.TrimPrefix(ins.Name, "/") // container_name if set
        if cname != "" && cname != svc {
            return cname // container_name wins when different
        }
        return svc
    }
    // otherwise use raw container name
    return strings.TrimPrefix(ins.Name, "/")
}

// hasInternalEnv checks INTERNAL env or label.
func hasInternalEnv(env []string, lbl map[string]string) bool {
    for _, e := range env {
        if strings.HasPrefix(e, "INTERNAL=") {
            return parseBool(strings.TrimPrefix(e, "INTERNAL="), false)
        }
    }
    return parseBool(lbl["service.internal"], false)
}

// hasGlobalIgnore checks SERVICE_IGNORE env or label.
func hasGlobalIgnore(env []string, lbl map[string]string) bool {
    for _, e := range env {
        if strings.HasPrefix(e, "SERVICE_IGNORE=") {
            return parseBool(strings.TrimPrefix(e, "SERVICE_IGNORE="), false)
        }
    }
    return parseBool(lbl["SERVICE_IGNORE"], false)
}

// containerIP returns the internal container IP.
func containerIP(ins *types.ContainerJSON) string {
    if ins.NetworkSettings == nil {
        return "127.0.0.1"
    }
    if ins.NetworkSettings.IPAddress != "" {
        return ins.NetworkSettings.IPAddress
    }
    for _, nw := range ins.NetworkSettings.Networks {
        if nw.IPAddress != "" {
            return nw.IPAddress
        }
    }
    return "127.0.0.1"
}

// firstHostIP finds the first non-loopback IPv4 of the host.
func firstHostIP() string {
	ifs, _ := net.Interfaces()
	for _, iface := range ifs {

		if iface.Flags&(net.FlagUp|net.FlagLoopback) != net.FlagUp {
			continue
		}

		if iface.Name == "docker0" ||
			strings.HasPrefix(iface.Name, "br-") ||
			strings.HasPrefix(iface.Name, "veth") {
			continue
		}

		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && !ip.IsLoopback() && ip.To4() != nil {
				return ip.String()
			}
		}
	}

	return "127.0.0.1"
}

// ----------------------------- main -----------------------
// main sets up everything and blocks until SIGINT/SIGTERM.
func main() {
    flag.Parse()

    be := newConsulBackend(*consulAddr, *insecure, consulToken)
    br, err := newBridge(be)
    if err != nil {
        log.Fatal(err)
    }
    defer func() {
        if err := br.Close(); err != nil {
            log.Printf("close error: %v", err)
        }
    }()

    ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer cancel()

    if err := br.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
        log.Fatal(err)
    }
}
