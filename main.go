package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const userAgent = "nextjs-recon/0.1 (+https://github.com/jonsnow/nextjs-recon)"

// ANSI color escapes — populated by initColors() iff stdout is a TTY and
// NO_COLOR isn't set. Otherwise all stay empty strings (zero-cost passthrough).
var (
	cReset  string
	cDim    string
	cPhase  string // bold blue   — phase markers
	cFact   string // bold yellow — buildId etc.
	cAPI    string // bold green  — /api/, /v1/, GraphQL endpoints
	cGQL    string // bold magenta
	cURL    string // bold cyan   — external URLs / subdomains
	cPath   string // dim white   — generic path hints (lower confidence)
	cSec    string // bold red    — hardcoded secrets / keys
	cSource string // dim         — "← chunks/foo.js"
)

func initColors() {
	if os.Getenv("NO_COLOR") != "" {
		return
	}
	fi, err := os.Stdout.Stat()
	if err != nil || (fi.Mode()&os.ModeCharDevice) == 0 {
		return
	}
	cReset = "\033[0m"
	cDim = "\033[2m"
	cPhase = "\033[1;34m"
	cFact = "\033[1;33m"
	cAPI = "\033[1;32m"
	cGQL = "\033[1;35m"
	cURL = "\033[1;36m"
	cPath = "\033[37m"
	cSec = "\033[1;31m"
	cSource = "\033[2m"
}

type Finding struct {
	Source   string `json:"source"`
	Endpoint string `json:"endpoint"`
	Kind     string `json:"kind"`
}

type Report struct {
	Target    string    `json:"target"`
	BuildID   string    `json:"buildId,omitempty"`
	JSFiles   []string  `json:"jsFiles"`
	Endpoints []string  `json:"apiEndpoints"`
	URLs      []string  `json:"externalUrls"`
	Secrets   []string  `json:"secrets"`
	Findings  []Finding `json:"findings"`
}

type config struct {
	target     string
	workers    int
	timeout    time.Duration
	insecure   bool
	jsonOut    bool
	verbose    bool
	maxDepth   int
	extraHosts bool
	showSource bool
	live       bool
	fetchMaps  bool
	routes     string
}

// streamer prints phase markers, fetch events, and findings as they happen.
// Output is mutex-serialized so concurrent goroutines don't interleave lines.
// Findings are deduped globally by (kind, endpoint) so a path discovered in
// five chunks prints once (the first source). The final summary still shows
// every source via -s.
type streamer struct {
	mu   sync.Mutex
	seen map[string]bool
	live bool
}

func newStreamer(live bool) *streamer {
	return &streamer{seen: map[string]bool{}, live: live}
}

func (s *streamer) phase(format string, a ...any) {
	if !s.live {
		return
	}
	s.mu.Lock()
	fmt.Printf("%s[*]%s "+format+"\n", append([]any{cPhase, cReset}, a...)...)
	s.mu.Unlock()
}

func (s *streamer) fact(format string, a ...any) {
	if !s.live {
		return
	}
	s.mu.Lock()
	fmt.Printf("%s[+]%s "+format+"\n", append([]any{cFact, cReset}, a...)...)
	s.mu.Unlock()
}

// finding records a finding; returns true the first time a given (kind,endpoint)
// is seen. In live mode it also prints the finding with its source chunk.
func (s *streamer) finding(f Finding) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := f.Kind + "|" + f.Endpoint
	if s.seen[key] {
		return false
	}
	s.seen[key] = true
	if s.live {
		tag, color := "[!]", ""
		switch {
		case f.Kind == "api":
			tag, color = "[api]", cAPI
		case f.Kind == "graphql":
			tag, color = "[gql]", cGQL
		case f.Kind == "url":
			tag, color = "[url]", cURL
		case f.Kind == "path":
			tag, color = "[pth]", cPath
		case strings.HasPrefix(f.Kind, "secret:"):
			tag, color = "[sec]", cSec
		}
		fmt.Printf("%s%-5s %s%s  %s← %s%s\n",
			color, tag, f.Endpoint, cReset,
			cSource, shortSource(f.Source), cReset)
	}
	return true
}

var (
	reNextData     = regexp.MustCompile(`(?s)<script[^>]+id="__NEXT_DATA__"[^>]*>(.*?)</script>`)
	reScriptSrc    = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	rePreloadHref  = regexp.MustCompile(`(?i)<link[^>]+rel=["']preload["'][^>]+href=["']([^"']+)["'][^>]*as=["']script["']`)
	rePreloadHref2 = regexp.MustCompile(`(?i)<link[^>]+as=["']script["'][^>]+href=["']([^"']+)["']`)
	reChunkRef     = regexp.MustCompile(`["'` + "`" + `](/?(?:_next/)?static/chunks/[^"'` + "`" + `\s,)(]+\.js)["'` + "`" + `]`)
	reSpecialChunk = regexp.MustCompile(`\d+===\w+\?["']?(static/chunks/[^"')\s]+\.js)["']?`)
	reMapEntry     = regexp.MustCompile(`(\d+):"([A-Za-z0-9_\-]+)"`)
	reManifestRoute = regexp.MustCompile(`"(/[A-Za-z0-9_\-/\[\]\.]*)"\s*:\s*\[`)

	reAPIPath  = regexp.MustCompile("[\"'`](/(?:api|v\\d+|graphql|rest|rpc|gql)(?:/[A-Za-z0-9_\\-./${}\\[\\]:?=&]*)?)[\"'`]")
	rePathLike = regexp.MustCompile("[\"'`](/[A-Za-z0-9_\\-]{2,}(?:/[A-Za-z0-9_\\-./${}\\[\\]:?=&]+){1,})[\"'`]")
	reFullURL  = regexp.MustCompile(`(?i)https?://[a-z0-9\-._~:/?#\[\]@!$&()*+;=%]+`)

	// Secret patterns. Names are intentionally short so they fit in the tag column.
	secretPatterns = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"aws-key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{"google-api", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)},
		{"github-pat", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`)},
		{"stripe-sk", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`)},
		{"stripe-pk", regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`)},
		{"slack-tok", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z\-]{10,}`)},
		{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)},
		{"firebase", regexp.MustCompile(`AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}`)},
		{"private-key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)},
		{"gcp-svc-acct", regexp.MustCompile(`"type"\s*:\s*"service_account"`)},
		// Generic api-key / secret / token assignment (keyword + literal).
		{"hardcoded-key", regexp.MustCompile(`(?i)(?:api[_\-]?key|secret|access[_\-]?token|auth[_\-]?token|bearer)["'` + "`" + `]?\s*[:=]\s*["'` + "`" + `]([A-Za-z0-9_\-]{20,})["'` + "`" + `]`)},
	}

	skipExt = []string{
		".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
		".woff", ".woff2", ".ttf", ".otf", ".eot",
		".map", ".mp4", ".webm", ".mp3", ".wav", ".pdf",
	}
	skipPathPrefix = []string{
		"/_next/", "/__next/", "/static/chunks/", "/_nuxt/",
	}
	skipHostContains = []string{
		"w3.org", "schema.org", "googletagmanager.com", "google-analytics.com",
		"fonts.googleapis.com", "fonts.gstatic.com", "gstatic.com",
		"sentry.io", "ingest.sentry", "datadoghq.com", "facebook.com",
		"twitter.com", "linkedin.com", "youtube.com", "doubleclick.net",
	}
)

func main() {
	initColors()
	cfg := config{}
	flag.StringVar(&cfg.target, "u", "", "target URL (e.g. https://example.com)")
	flag.IntVar(&cfg.workers, "c", 25, "concurrent workers")
	flag.DurationVar(&cfg.timeout, "t", 15*time.Second, "per-request timeout")
	flag.BoolVar(&cfg.insecure, "k", true, "skip TLS verification")
	flag.BoolVar(&cfg.jsonOut, "json", false, "emit JSON output")
	flag.BoolVar(&cfg.verbose, "v", false, "verbose logging to stderr")
	flag.IntVar(&cfg.maxDepth, "depth", 2, "max JS chunk reference depth")
	flag.BoolVar(&cfg.extraHosts, "all-hosts", false, "include third-party URLs in output")
	flag.BoolVar(&cfg.showSource, "s", false, "annotate each endpoint/URL with the JS file it was found in")
	flag.BoolVar(&cfg.showSource, "source", false, "annotate each endpoint/URL with the JS file it was found in")
	flag.BoolVar(&cfg.live, "live", false, "stream progress and findings as they're discovered")
	flag.BoolVar(&cfg.live, "L", false, "stream progress and findings as they're discovered")
	flag.BoolVar(&cfg.fetchMaps, "maps", true, "try fetching <chunk>.js.map for each JS file and scan original source")
	flag.StringVar(&cfg.routes, "routes", "", "extra route paths to crawl, comma-separated (e.g. /admin,/login,/dashboard)")
	flag.Parse()

	if cfg.target == "" && flag.NArg() > 0 {
		cfg.target = flag.Arg(0)
	}
	if cfg.target == "" {
		fmt.Fprintln(os.Stderr, "usage: nextjs-recon -u https://example.com [flags]")
		flag.PrintDefaults()
		os.Exit(2)
	}
	if !strings.HasPrefix(cfg.target, "http://") && !strings.HasPrefix(cfg.target, "https://") {
		cfg.target = "https://" + cfg.target
	}
	cfg.target = strings.TrimRight(cfg.target, "/")

	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(cfg config) error {
	client := newClient(cfg)
	base, err := url.Parse(cfg.target)
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	// JSON output is one structured doc — live streaming would corrupt it.
	if cfg.jsonOut && cfg.live {
		fmt.Fprintln(os.Stderr, "[!] -live ignored when -json is set")
		cfg.live = false
	}

	stream := newStreamer(cfg.live)

	logf := func(format string, a ...any) {
		if cfg.verbose {
			fmt.Fprintf(os.Stderr, "[*] "+format+"\n", a...)
		}
	}

	stream.phase("Fetching %s", cfg.target)
	logf("fetching %s", cfg.target)
	html, _, err := fetch(client, cfg.target)
	if err != nil {
		return fmt.Errorf("fetch target: %w", err)
	}

	buildID := extractBuildID(html)
	if buildID != "" {
		stream.fact("Next.js buildId: %s", buildID)
		logf("buildId: %s", buildID)
	}

	seedSet := map[string]bool{}
	for _, u := range discoverSeeds(html, base, buildID) {
		seedSet[u] = true
	}
	stream.phase("Discovered %d seed JS candidates", len(seedSet))
	logf("seed JS candidates: %d", len(seedSet))

	// Extra routes: explicit (-routes) plus auto-discovered from _buildManifest.js
	// when we have a buildId. Each extra route is fetched as HTML and its seed JS
	// merged into the pool.
	extraRoutes := parseRoutesFlag(cfg.routes)
	jsBodies := fetchAll(client, keysOfSet(seedSet), cfg.workers, logf, stream)

	if buildID != "" {
		manifestURL := strings.TrimRight(cfg.target, "/") + "/_next/static/" + buildID + "/_buildManifest.js"
		if body, status, err := fetch(client, manifestURL); err == nil && status < 400 {
			for _, r := range discoverManifestRoutes(body) {
				extraRoutes = append(extraRoutes, r)
			}
		}
	}

	if len(extraRoutes) > 0 {
		extraRoutes = uniqStrings(extraRoutes)
		stream.phase("Crawling %d extra routes", len(extraRoutes))
		logf("extra routes: %d", len(extraRoutes))
		newSeeds := map[string]bool{}
		for _, path := range extraRoutes {
			ru := strings.TrimRight(cfg.target, "/") + path
			rhtml, status, err := fetch(client, ru)
			if err != nil || status >= 400 {
				logf("route %s: %v (status %d)", ru, err, status)
				continue
			}
			for _, u := range discoverSeeds(rhtml, base, buildID) {
				if !seedSet[u] {
					seedSet[u] = true
					newSeeds[u] = true
				}
			}
		}
		if len(newSeeds) > 0 {
			stream.phase("Routes added %d new JS files", len(newSeeds))
			extra := fetchAll(client, keysOfSet(newSeeds), cfg.workers, logf, stream)
			for k, v := range extra {
				jsBodies[k] = v
			}
		}
	}

	if cfg.maxDepth > 1 {
		visited := map[string]bool{}
		for u := range jsBodies {
			visited[u] = true
		}
		current := jsBodies
		for d := 1; d < cfg.maxDepth; d++ {
			next := map[string]string{}
			for src, body := range current {
				for _, abs := range discoverChunksInBody(src, body, base) {
					if visited[abs] {
						continue
					}
					visited[abs] = true
					next[abs] = ""
				}
			}
			if len(next) == 0 {
				break
			}
			stream.phase("Depth %d: fetching %d new chunks", d+1, len(next))
			logf("depth %d: %d new chunks", d+1, len(next))
			fetched := fetchAll(client, keys(next), cfg.workers, logf, stream)
			for k, v := range fetched {
				jsBodies[k] = v
				next[k] = v
			}
			current = next
		}
	}

	if cfg.fetchMaps {
		stream.phase("Trying sourcemaps for %d JS files", len(jsBodies))
		maps := fetchSourcemaps(client, keys(jsBodies), cfg.workers, logf, stream)
		for k, v := range maps {
			jsBodies[k] = v
		}
		if len(maps) > 0 {
			stream.phase("Recovered %d original source files from sourcemaps", len(maps))
		}
	}

	stream.phase("Analyzing %d JS files", len(jsBodies))
	logf("analyzing %d JS files", len(jsBodies))
	findings := analyzeAll(jsBodies, base, cfg.extraHosts, stream)

	report := buildReport(cfg.target, buildID, jsBodies, findings)
	if cfg.live {
		stream.phase("Done. %d JS files, %d endpoints, %d URLs, %d secrets",
			len(report.JSFiles), len(report.Endpoints), len(report.URLs), len(report.Secrets))
		if !cfg.showSource && !cfg.jsonOut {
			return nil
		}
		fmt.Println()
	}
	return emit(report, cfg.jsonOut, cfg.showSource)
}

func newClient(cfg config) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: cfg.insecure},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: cfg.timeout,
		DisableCompression:    false,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   cfg.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func fetch(client *http.Client, u string) (string, int, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 25<<20))
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(body), resp.StatusCode, nil
}

func fetchAll(client *http.Client, urls []string, workers int, logf func(string, ...any), s *streamer) map[string]string {
	out := make(map[string]string, len(urls))
	var mu sync.Mutex
	jobs := make(chan string)
	var wg sync.WaitGroup
	if workers < 1 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				body, status, err := fetch(client, u)
				if err != nil {
					logf("fetch %s: %v", u, err)
					continue
				}
				if status >= 400 {
					logf("fetch %s: status %d", u, status)
					continue
				}
				mu.Lock()
				out[u] = body
				mu.Unlock()
			}
		}()
	}
	for _, u := range urls {
		jobs <- u
	}
	close(jobs)
	wg.Wait()
	return out
}

// fetchSourcemaps tries `<jsURL>.js.map` (or `<jsURL>.map`) for each JS URL.
// When a sourcemap parses, every entry of (sources, sourcesContent) is added
// to the returned map keyed by a synthetic URL `<mapURL>#<originalPath>` so the
// existing analyzer can scan the original (un-minified) source.
func fetchSourcemaps(client *http.Client, jsURLs []string, workers int, logf func(string, ...any), s *streamer) map[string]string {
	out := make(map[string]string)
	var mu sync.Mutex
	jobs := make(chan string)
	var wg sync.WaitGroup
	if workers < 1 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				mapURL := u + ".map"
				body, status, err := fetch(client, mapURL)
				if err != nil || status >= 400 {
					continue
				}
				var sm struct {
					Sources        []string `json:"sources"`
					SourcesContent []string `json:"sourcesContent"`
				}
				if err := json.Unmarshal([]byte(body), &sm); err != nil {
					continue
				}
				added := 0
				for i, content := range sm.SourcesContent {
					if i >= len(sm.Sources) || content == "" {
						continue
					}
					synthetic := mapURL + "#" + sm.Sources[i]
					mu.Lock()
					out[synthetic] = content
					mu.Unlock()
					added++
				}
				if added > 0 {
					s.fact("Sourcemap recovered: %s (%d original files)", shortSource(mapURL), added)
					logf("sourcemap %s: %d sources", mapURL, added)
				}
			}
		}()
	}
	for _, u := range jsURLs {
		jobs <- u
	}
	close(jobs)
	wg.Wait()
	return out
}

func extractBuildID(html string) string {
	m := reNextData.FindStringSubmatch(html)
	if len(m) < 2 {
		return ""
	}
	var data struct {
		BuildID string `json:"buildId"`
	}
	if err := json.Unmarshal([]byte(m[1]), &data); err != nil {
		return ""
	}
	return data.BuildID
}

func discoverSeeds(html string, base *url.URL, buildID string) []string {
	seen := map[string]bool{}
	add := func(raw string) {
		abs := resolve(base, raw)
		if abs == "" || !strings.HasSuffix(strings.SplitN(abs, "?", 2)[0], ".js") {
			return
		}
		if !allowedAssetHost(base, abs) {
			return
		}
		seen[abs] = true
	}

	for _, m := range reScriptSrc.FindAllStringSubmatch(html, -1) {
		add(m[1])
	}
	for _, m := range rePreloadHref.FindAllStringSubmatch(html, -1) {
		add(m[1])
	}
	for _, m := range rePreloadHref2.FindAllStringSubmatch(html, -1) {
		add(m[1])
	}
	for _, m := range reChunkRef.FindAllStringSubmatch(html, -1) {
		add(m[1])
	}

	if buildID != "" {
		add("/_next/static/" + buildID + "/_buildManifest.js")
		add("/_next/static/" + buildID + "/_ssgManifest.js")
		add("/_next/static/" + buildID + "/_middlewareManifest.js")
	}

	urls := make([]string, 0, len(seen))
	for u := range seen {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	return urls
}

func resolve(base *url.URL, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return base.ResolveReference(u).String()
}

func sameHost(base *url.URL, abs string) bool {
	u, err := url.Parse(abs)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, base.Host)
}

// allowedAssetHost accepts the URL if it's on the same host, on a sibling
// subdomain of the same registered domain (e.g. static.capital.com for capital.com),
// or — regardless of host — clearly a Next.js static asset path. The Next.js
// path heuristic catches CDN-fronted bundles on unrelated domains.
func allowedAssetHost(base *url.URL, abs string) bool {
	u, err := url.Parse(abs)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, base.Host) {
		return true
	}
	if strings.Contains(u.Path, "/_next/static/") || strings.Contains(u.Path, "/_next/data/") {
		return true
	}
	if siblingDomain(base.Host, u.Host) {
		return true
	}
	return false
}

// siblingDomain is a best-effort check (no public suffix list) that two hosts
// share the same last two labels — e.g. static.capital.com vs capital.com.
// It will be wrong for some ccTLDs like .co.uk, which is acceptable for recon.
func siblingDomain(a, b string) bool {
	a = strings.ToLower(a)
	b = strings.ToLower(b)
	la := strings.Split(a, ".")
	lb := strings.Split(b, ".")
	if len(la) < 2 || len(lb) < 2 {
		return false
	}
	return la[len(la)-1] == lb[len(lb)-1] && la[len(la)-2] == lb[len(lb)-2]
}

// discoverChunksInBody finds all chunk URLs referenced by or reconstructible
// from a JS body, resolved to absolute URLs and filtered by allowedAssetHost.
func discoverChunksInBody(sourceURL, body string, base *url.URL) []string {
	srcBase, err := url.Parse(sourceURL)
	if err != nil {
		srcBase = base
	}
	seen := map[string]bool{}
	var out []string
	add := func(abs string) {
		if abs == "" || seen[abs] || !allowedAssetHost(base, abs) {
			return
		}
		seen[abs] = true
		out = append(out, abs)
	}

	for _, ref := range reChunkRef.FindAllStringSubmatch(body, -1) {
		path := ref[1]
		if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
			add(path)
			continue
		}
		if strings.HasPrefix(path, "/_next/") || strings.HasPrefix(path, "_next/") {
			add(resolve(srcBase, "/"+strings.TrimPrefix(path, "/")))
			continue
		}
		add(resolveChunkURL(sourceURL, path))
	}

	for _, path := range extractWebpackChunks(body) {
		add(resolveChunkURL(sourceURL, path))
	}

	return out
}

// extractWebpackChunks reconstructs chunk filenames from a webpack runtime body
// by parsing the chunk-id → prefix and chunk-id → content-hash maps that
// `__webpack_require__.u` consults. Also picks up hard-coded special cases
// like `5376===e?"static/chunks/5376-abc.js"`.
func extractWebpackChunks(body string) []string {
	seen := map[string]bool{}
	var out []string
	push := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}

	for _, m := range reSpecialChunk.FindAllStringSubmatch(body, -1) {
		push(m[1])
	}

	idx := -1
	for _, marker := range []string{".u=function", ".u=e=>", ".u=(e)=>", ".u=function(e)"} {
		if i := strings.Index(body, marker); i >= 0 {
			idx = i
			break
		}
	}
	if idx < 0 {
		return out
	}

	tail := body[idx:]
	end := len(tail)
	for _, term := range []string{".miniCssF=", ".g=function", ".g=()", ".o=("} {
		if i := strings.Index(tail, term); i > 50 && i < end {
			end = i
		}
	}
	window := tail[:end]

	entries := reMapEntry.FindAllStringSubmatch(window, -1)
	prefixMap := map[string]string{}
	hashMap := map[string]string{}
	for _, e := range entries {
		id, val := e[1], e[2]
		switch {
		case len(val) >= 12:
			hashMap[id] = val
		case len(val) <= 10:
			if _, has := hashMap[id]; !has {
				prefixMap[id] = val
			}
		}
	}

	for id, hash := range hashMap {
		if prefix, ok := prefixMap[id]; ok {
			push("static/chunks/" + prefix + "." + hash + ".js")
		} else {
			push("static/chunks/" + id + "." + hash + ".js")
		}
	}
	return out
}

// resolveChunkURL turns a chunk path like "static/chunks/foo.js" into an
// absolute URL by anchoring it at the `/_next/` segment of the source JS URL.
// This handles Next.js setups where assets live behind a path-prefixed CDN
// (e.g. https://static.example.com/build-id/app/_next/static/chunks/foo.js).
func resolveChunkURL(sourceURL, chunkPath string) string {
	chunkPath = strings.TrimPrefix(chunkPath, "/")
	chunkPath = strings.TrimPrefix(chunkPath, "_next/")
	idx := strings.Index(sourceURL, "/_next/")
	if idx < 0 {
		return ""
	}
	return sourceURL[:idx+len("/_next/")] + chunkPath
}

func parseRoutesFlag(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		out = append(out, p)
	}
	return out
}

// discoverManifestRoutes pulls every "/route": [ ... key from a _buildManifest.js
// body. Skips dynamic ([id]) routes since we can't fill in real values.
func discoverManifestRoutes(body string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range reManifestRoute.FindAllStringSubmatch(body, -1) {
		p := m[1]
		if p == "/" || strings.Contains(p, "[") {
			continue
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func uniqStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func keysOfSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func analyzeAll(jsBodies map[string]string, base *url.URL, extraHosts bool, s *streamer) []Finding {
	var out []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)

	for src, body := range jsBodies {
		wg.Add(1)
		sem <- struct{}{}
		go func(src, body string) {
			defer wg.Done()
			defer func() { <-sem }()
			found := analyze(src, body, base, extraHosts, s)
			if len(found) > 0 {
				mu.Lock()
				out = append(out, found...)
				mu.Unlock()
			}
		}(src, body)
	}
	wg.Wait()
	return out
}

func analyze(src, body string, base *url.URL, extraHosts bool, s *streamer) []Finding {
	var findings []Finding
	dedupe := map[string]bool{}
	push := func(endpoint, kind string) {
		key := kind + "|" + endpoint
		if dedupe[key] {
			return
		}
		dedupe[key] = true
		f := Finding{Source: src, Endpoint: endpoint, Kind: kind}
		findings = append(findings, f)
		s.finding(f)
	}

	for _, m := range reAPIPath.FindAllStringSubmatch(body, -1) {
		p := cleanPath(m[1])
		if p == "" || shouldSkipPath(p) {
			continue
		}
		kind := "api"
		if strings.Contains(p, "graphql") || strings.Contains(p, "/gql") {
			kind = "graphql"
		}
		push(p, kind)
	}

	for _, m := range rePathLike.FindAllStringSubmatch(body, -1) {
		p := cleanPath(m[1])
		if p == "" || shouldSkipPath(p) {
			continue
		}
		if !looksLikeEndpoint(p) {
			continue
		}
		push(p, "path")
	}

	for _, m := range reFullURL.FindAllString(body, -1) {
		u := cleanURL(m)
		if u == "" || shouldSkipURL(u) {
			continue
		}
		if !extraHosts && !sameHost(base, u) {
			parsed, _ := url.Parse(u)
			if parsed == nil {
				continue
			}
			if !siblingDomain(base.Host, parsed.Host) && !isLikelyAPI(parsed) {
				continue
			}
		}
		push(u, "url")
	}

	for _, sp := range secretPatterns {
		for _, m := range sp.re.FindAllStringSubmatch(body, -1) {
			val := m[0]
			if len(m) > 1 && m[1] != "" {
				val = m[1]
			}
			push(val, "secret:"+sp.name)
		}
	}

	return findings
}

func cleanPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimRight(p, ",;:")
	if i := strings.IndexAny(p, "\"'`"); i >= 0 {
		p = p[:i]
	}
	return p
}

func cleanURL(u string) string {
	u = strings.TrimRight(u, ".,;:\"'`)]}>")
	return u
}

func shouldSkipPath(p string) bool {
	lp := strings.ToLower(p)
	for _, ext := range skipExt {
		if strings.HasSuffix(lp, ext) {
			return true
		}
	}
	for _, pre := range skipPathPrefix {
		if strings.HasPrefix(lp, pre) {
			return true
		}
	}
	if len(p) > 300 {
		return true
	}
	return false
}

func shouldSkipURL(u string) bool {
	lu := strings.ToLower(u)
	for _, ext := range skipExt {
		if strings.HasSuffix(lu, ext) {
			return true
		}
	}
	for _, h := range skipHostContains {
		if strings.Contains(lu, h) {
			return true
		}
	}
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" {
		return true
	}
	return false
}

func looksLikeEndpoint(p string) bool {
	if strings.Count(p, "/") < 2 {
		return false
	}
	hints := []string{"user", "auth", "login", "logout", "session", "token", "account",
		"signup", "register", "profile", "admin", "search", "query", "upload",
		"download", "data", "list", "fetch", "submit", "create", "update", "delete",
		"webhook", "callback", "oauth", "verify", "config", "settings", "subscribe",
		"checkout", "payment", "order", "cart", "product", "item", "message", "notify"}
	lp := strings.ToLower(p)
	for _, h := range hints {
		if strings.Contains(lp, h) {
			return true
		}
	}
	return false
}

func isLikelyAPI(u *url.URL) bool {
	host := strings.ToLower(u.Host)
	if strings.HasPrefix(host, "api.") || strings.Contains(host, ".api.") ||
		strings.HasPrefix(host, "api-") || strings.Contains(host, "-api.") ||
		strings.Contains(host, "-api-") || strings.Contains(host, ".api-") ||
		strings.Contains(host, "graphql") || strings.HasPrefix(host, "gql.") ||
		strings.HasPrefix(host, "backend.") || strings.Contains(host, ".backend.") ||
		strings.HasPrefix(host, "backend-") || strings.Contains(host, "-backend.") {
		return true
	}
	lp := strings.ToLower(u.Path)
	if strings.HasPrefix(lp, "/api/") || strings.HasPrefix(lp, "/v1/") ||
		strings.HasPrefix(lp, "/v2/") || strings.HasPrefix(lp, "/v3/") ||
		strings.Contains(lp, "/graphql") || strings.HasPrefix(lp, "/rest/") {
		return true
	}
	return false
}

func buildReport(target, buildID string, jsBodies map[string]string, findings []Finding) Report {
	apiSet := map[string]bool{}
	urlSet := map[string]bool{}
	secSet := map[string]bool{}
	for _, f := range findings {
		switch {
		case f.Kind == "api", f.Kind == "graphql", f.Kind == "path":
			apiSet[f.Endpoint] = true
		case f.Kind == "url":
			urlSet[f.Endpoint] = true
		case strings.HasPrefix(f.Kind, "secret:"):
			secSet[f.Endpoint] = true
		}
	}
	r := Report{
		Target:    target,
		BuildID:   buildID,
		JSFiles:   keys(jsBodies),
		Endpoints: sortedKeys(apiSet),
		URLs:      sortedKeys(urlSet),
		Secrets:   sortedKeys(secSet),
		Findings:  findings,
	}
	return r
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func emit(r Report, asJSON, showSource bool) error {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}

	sources := map[string][]string{}
	if showSource {
		seen := map[string]map[string]bool{}
		for _, f := range r.Findings {
			if seen[f.Endpoint] == nil {
				seen[f.Endpoint] = map[string]bool{}
			}
			short := shortSource(f.Source)
			if !seen[f.Endpoint][short] {
				seen[f.Endpoint][short] = true
				sources[f.Endpoint] = append(sources[f.Endpoint], short)
			}
		}
		for k := range sources {
			sort.Strings(sources[k])
		}
	}

	fmt.Printf("[+] Target:           %s\n", r.Target)
	if r.BuildID != "" {
		fmt.Printf("[+] Next.js buildId:  %s\n", r.BuildID)
	}
	fmt.Printf("[+] JS files fetched: %d\n", len(r.JSFiles))
	fmt.Println()
	fmt.Printf("[+] API endpoints (%d):\n", len(r.Endpoints))
	for _, e := range r.Endpoints {
		printItem(e, sources[e], showSource)
	}
	fmt.Println()
	fmt.Printf("[+] External URLs (%d):\n", len(r.URLs))
	for _, u := range r.URLs {
		printItem(u, sources[u], showSource)
	}
	if len(r.Secrets) > 0 {
		fmt.Println()
		fmt.Printf("[!] Possible secrets (%d):\n", len(r.Secrets))
		for _, sec := range r.Secrets {
			printItem(sec, sources[sec], showSource)
		}
	}
	return nil
}

func printItem(item string, srcs []string, showSource bool) {
	if !showSource || len(srcs) == 0 {
		fmt.Printf("    %s\n", item)
		return
	}
	fmt.Printf("    %s\n", item)
	for _, s := range srcs {
		fmt.Printf("        ← %s\n", s)
	}
}

// shortSource trims an asset URL to the most useful suffix for display.
// E.g. https://static.x.com/abc/_next/static/chunks/app/login/page-x.js
//      → chunks/app/login/page-x.js
// For sourcemap-derived synthetic URLs (<chunk>.js.map#<orig-path>) it shows
// chunks/foo.js.map → orig/path.ts.
func shortSource(u string) string {
	if i := strings.Index(u, ".js.map#"); i >= 0 {
		chunk := u[:i+len(".js.map")]
		orig := u[i+len(".js.map#"):]
		if j := strings.Index(chunk, "/_next/static/"); j >= 0 {
			chunk = chunk[j+len("/_next/static/"):]
		} else if j := strings.LastIndex(chunk, "/"); j >= 0 {
			chunk = chunk[j+1:]
		}
		return chunk + " → " + orig
	}
	if i := strings.Index(u, "/_next/static/"); i >= 0 {
		return u[i+len("/_next/static/"):]
	}
	if i := strings.LastIndex(u, "/"); i >= 0 {
		return u[i+1:]
	}
	return u
}
