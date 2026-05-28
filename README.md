# nextjs-recon

A fast, focused recon tool for Next.js applications. Point it at a target URL and it pulls every client-side JS chunk the browser would load — including lazy-loaded webpack chunks that aren't referenced in the HTML — then mines them for API endpoints, sibling subdomains, internal URLs, and hardcoded secrets.

Written in Go, single static binary, zero runtime dependencies.

## What it does

- **Discovers every JS file** the Next.js app ships, including:
  - Same-host chunks under `/_next/static/chunks/`
  - CDN-fronted chunks on sibling hosts (e.g. `static.example.com`)
  - Lazy-loaded chunks reconstructed from the webpack runtime maps (chunks that only get fetched after navigation)
  - Pages/App Router manifests (`_buildManifest.js`, `_ssgManifest.js`, `_middlewareManifest.js`)
- **Extracts findings** from every chunk:
  - REST API endpoints (`/api/`, `/v1/`, `/v2/`, etc.)
  - GraphQL endpoints
  - External URLs and sibling backend hosts (e.g. `api.target.com`)
  - Internal route paths
  - Hardcoded secrets (AWS keys, Google API keys, GitHub PATs, Stripe keys, JWTs, Slack tokens, PEM private keys, generic `api_key=…` literals)
- **Fetches sourcemaps** when exposed (`<chunk>.js.map`) and scans the original un-minified source for cleaner, more accurate results.
- **Crawls extra routes** so the tool sees the chunks shipped by `/admin`, `/login`, etc., not just the homepage. Auto-discovers static routes from `_buildManifest.js`.
- **Annotates findings** with the JS file each one came from (`-s`).
- **Streams output live** with color-coded tags as findings are discovered (`-live`).

## Installation

### From source

```bash
git clone https://github.com/mathavamoorthi/next-recon.git
cd next-recon
go build -o nextjs-recon .
```

Requires Go 1.24+. No external dependencies — pure standard library.

### Direct install

```bash
go install github.com/mathavamoorthi/next-recon@latest
```

## Quickstart

```bash
# Default — quiet scan, summary at the end
./nextjs-recon -u https://target.com

# Live progress with color-coded findings
./nextjs-recon -u https://target.com -live

# Live + show which JS chunk each finding came from
./nextjs-recon -u https://target.com -live -s

# Crawl multiple entry pages (different routes ship different chunks)
./nextjs-recon -u https://target.com -routes "/admin,/login,/dashboard" -live

# JSON output for piping into other tools
./nextjs-recon -u https://target.com -json | jq '.apiEndpoints[]'
```

## Flags

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `-u` | string | *(required)* | Target URL, e.g. `https://example.com` |
| `-c` | int | `25` | Concurrent HTTP workers |
| `-t` | duration | `15s` | Per-request timeout |
| `-k` | bool | `true` | Skip TLS verification |
| `-depth` | int | `2` | How many levels of chunk-reference recursion to follow |
| `-routes` | string | `""` | Extra entry-page paths, comma-separated |
| `-maps` | bool | `true` | Try fetching `<chunk>.js.map` for each JS file |
| `-all-hosts` | bool | `false` | Keep third-party URLs that aren't sibling/API hosts |
| `-live` / `-L` | bool | `false` | Stream findings as they're discovered |
| `-s` / `-source` | bool | `false` | Annotate each finding with its source JS file |
| `-json` | bool | `false` | Emit a structured JSON report |
| `-v` | bool | `false` | Verbose stderr logging |

## Output

### Default (text summary)

```
[+] Target:           https://target.com
[+] Next.js buildId:  abc123def456
[+] JS files fetched: 47

[+] API endpoints (23):
    /api/auth/signin
    /api/users/me
    /api/graphql
    ...

[+] External URLs (8):
    https://api.target.com
    https://cdn.target.com
    ...

[!] Possible secrets (1):
    AKIAIOSFODNN7EXAMPLE
```

### Live mode (`-live`)

```
[*] Fetching https://target.com
[+] Next.js buildId: abc123def456
[*] Discovered 26 seed JS candidates
[*] Crawling 3 extra routes
[*] Routes added 8 new JS files
[*] Depth 2: fetching 6 new chunks
[*] Trying sourcemaps for 40 JS files
[+] Sourcemap recovered: chunks/main.js.map (47 original files)
[*] Analyzing 87 JS files
[api] /api/auth/signin       ← chunks/6489-…js
[api] /api/users/me          ← chunks/main.js.map → src/api/users.ts
[url] https://api.target.com ← chunks/1443-…js
[sec] AKIAIOSFODNN7EXAMPLE   ← chunks/main.js.map → src/config/aws.ts
[*] Done. 40 JS files, 47 endpoints, 12 URLs, 1 secrets
```

Live-mode tag legend:

| Tag | Color | Meaning |
|---|---|---|
| `[*]` | blue | Phase marker |
| `[+]` | yellow | Fact (buildId, sourcemap recovered) |
| `[api]` | green | REST endpoint |
| `[gql]` | magenta | GraphQL endpoint |
| `[url]` | cyan | External URL / sibling subdomain |
| `[pth]` | white | Generic path hint (lower confidence) |
| `[sec]` | red | Possible secret |
| `← src` | dim | Source chunk |

Colors auto-disable when output is piped. `NO_COLOR=1` forces them off even on a TTY.

### JSON (`-json`)

```json
{
  "target": "https://target.com",
  "buildId": "abc123def456",
  "jsFiles": ["https://target.com/_next/static/chunks/…"],
  "apiEndpoints": ["/api/auth/signin", "/api/users/me"],
  "externalUrls": ["https://api.target.com"],
  "secrets": ["AKIAIOSFODNN7EXAMPLE"],
  "findings": [
    {
      "source": "https://target.com/_next/static/chunks/main-…js",
      "endpoint": "/api/auth/signin",
      "kind": "api"
    }
  ]
}
```

## How it works

1. **Fetch the HTML** of the target. Parse `__NEXT_DATA__` for the `buildId` and discover seed JS candidates from `<script src>`, `<link rel=preload>`, and any inline `static/chunks/…` references.
2. **Worker pool fetches** every seed JS file concurrently (25 workers by default), reusing TLS connections aggressively.
3. **Webpack runtime reconstruction**: parses the `__webpack_require__.u` chunk-id maps embedded in webpack runtime bundles and reconstructs the URLs of lazy-loaded chunks that the browser would only fetch after navigation. This catches chunks no other static analyzer would find.
4. **Depth-2 recursion**: each fetched chunk is re-scanned for further chunk references and the loop continues until no new chunks appear or `-depth` is hit.
5. **Multi-route crawl**: extra entry pages (`-routes`) and routes auto-discovered from `_buildManifest.js` are also fetched as HTML and added to the seed pool.
6. **Sourcemap recovery**: for every JS file, the tool tries `<url>.js.map`. When present, original source files (with real identifier names) are added to the analyzer pool.
7. **Regex analysis runs in parallel** across every JS body (16 goroutines) extracting API paths, GraphQL endpoints, external URLs, internal routes, and secrets. Per-file local dedupe + global dedupe by `(kind, endpoint)`.
8. **Filter** known-noise hosts (analytics, fonts, social CDNs) and report.

A typical Next.js site finishes in 1–3 seconds even with hundreds of chunks.

## Scope

### Works well on

- Next.js apps (App Router or Pages Router) — same-host or CDN-fronted
- Apps with lazy-loaded chunks (App Router with route splitting)
- Apps with sibling-subdomain APIs (e.g. `api.target.com`, `static.target.com`)
- Both authenticated and unauthenticated landing pages (only public surface is analyzed)

### Limited or won't work on

- **Non-Next.js sites** (Nuxt, Remix, plain React/Vite, Angular, Svelte) — chunk path conventions don't match
- **Bot-protected targets** (Cloudflare challenge, Akamai Bot Manager, PerimeterX) — the HTML fetch fails and there's nothing to analyze
- **Auth-walled apps** — only the public surface is reachable; internal chunks need session cookies (not supported)
- **Pages where JS is loaded only via service workers** — no `<script>` tags to seed from

### Quick sanity check

If you're unsure a site is Next.js:

```bash
curl -s https://target.com | grep -o '/_next/static/[^"]*' | head -1
```

If that prints anything, the tool will work.

## Examples

```bash
# Basic recon
./nextjs-recon -u https://target.com -live

# Aggressive scan: live, sourced, deeper recursion, custom routes
./nextjs-recon -u https://target.com -live -s -depth 3 -routes "/admin,/api-docs"

# Slower target, longer timeout, fewer workers
./nextjs-recon -u https://target.com -t 30s -c 10 -live

# Include third-party URLs (CDNs, analytics, etc.)
./nextjs-recon -u https://target.com -all-hosts -live

# Pipe endpoints to ffuf
./nextjs-recon -u https://target.com -json | jq -r '.apiEndpoints[]' | ffuf -u "https://target.com/FUZZ" -w -

# Save full report
./nextjs-recon -u https://target.com -json > target-recon.json
```

## Authorization

Only run this tool against:

- Sites you own or operate
- Bug bounty programs that explicitly authorize automated recon
- CTF challenges or deliberately vulnerable test apps
- Targets you have written authorization to assess

The tool only makes unauthenticated GET requests to assets the browser would fetch anyway, but unauthorized scanning of production systems can still violate computer-misuse laws in many jurisdictions.

## License

MIT
